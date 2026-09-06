package zip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"golang.org/x/sync/errgroup"

	"github.com/klauspost/compress/zstd"
)

func TestZstdCompressionLoop(t *testing.T) {
	data := []byte("zstd compression test data with some repetitive content content content")
	buf := new(bytes.Buffer)

	// Compress
	zw := NewWriter(buf)
	w, err := zw.CreateHeader(&FileHeader{
		Name:   "test.zstd",
		Method: ZSTD,
	})
	if err != nil {
		t.Fatalf("failed to create zstd entry: %v", err)
	}
	mustWrite(t, w, data)
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	// Decompress
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("failed to create reader: %v", err)
	}
	f := zr.File[0]
	if f.Method != ZSTD {
		t.Errorf("expected method ZSTD, got %d", f.Method)
	}
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("failed to open zstd file: %v", err)
	}
	closeAt(t, rc)
	decompressed, _ := io.ReadAll(rc)

	if !bytes.Equal(decompressed, data) {
		t.Errorf("data mismatch: expected %q, got %q", string(data), string(decompressed))
	}
}

func TestZstdConcurrencyStress(t *testing.T) {
	data := []byte("repetitive data repetitive data")
	ctx := context.Background()
	errGrp, _ := errgroup.WithContext(ctx)

	for i := 0; i < 20; i++ {
		errGrp.Go(func() error {
			// This runs off the test goroutine, so a failure has to come
			// back as a returned error: t.Fatal (and with it every must*
			// helper) may only be called from the goroutine running the
			// test.
			buf := new(bytes.Buffer)
			zw := NewWriter(buf)
			w, err := zw.Create("test")
			if err != nil {
				return err
			}
			if _, err := w.Write(data); err != nil {
				return err
			}
			if err := zw.Close(); err != nil {
				return err
			}

			zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				return err
			}
			rc, err := zr.File[0].Open()
			if err != nil {
				return err
			}
			defer func() { _ = rc.Close() }()
			res, err := io.ReadAll(rc)
			if err != nil {
				return err
			}
			if !bytes.Equal(res, data) {
				return fmt.Errorf("data corruption")
			}
			return nil
		})
	}

	if err := errGrp.Wait(); err != nil {
		t.Errorf("stress test failed: %v", err)
	}
}

// untilPoolHit runs check until it reports that a writer came back out of the
// pool it was just put into, up to attempts times.
//
// A miss proves nothing, because the runtime is entitled to lose the value and
// under the race detector it loses it on purpose: sync.Pool.Put opens with
//
//	if race.Enabled {
//		if runtime_randn(4) == 0 {
//			// Randomly drop x on floor.
//			return
//		}
//	}
//
// so one Put in four never reaches the pool, precisely so that no code can
// depend on reuse. A garbage collection empties the pool as well, and Put
// stores into the private slot of the P the caller is running on while a Get
// that has migrated to another P cannot take it back. Asserting on a single
// round trip therefore failed several runs in ten under -race. A hit, on the
// other hand, cannot happen unless Close really did return the writer to the
// pool its level maps to, so it is conclusive and the check retries until one
// lands. What the runtime cannot take back -- which pool a level maps to, and
// which pool a writer is bound to -- is asserted outright and exactly.
func untilPoolHit(attempts int, check func() bool) bool {
	for i := 0; i < attempts; i++ {
		if check() {
			return true
		}
	}
	return false
}

func TestLevelAwarePooling(t *testing.T) {
	// Каждый уровень отображается в свой собственный пул, и одинаковые
	// уровни всегда дают один и тот же пул.
	flate4 := getFlateWriterPool(4)
	flate5 := getFlateWriterPool(5)
	if flate4 != getFlateWriterPool(4) {
		t.Error("flate level 4 does not map to a stable pool")
	}
	if flate4 == flate5 {
		t.Error("flate levels 4 and 5 share a pool")
	}
	zstd4 := getZstdWriterPool(4)
	zstd5 := getZstdWriterPool(5)
	if zstd4 != getZstdWriterPool(4) {
		t.Error("zstd level 4 does not map to a stable pool")
	}
	if zstd4 == zstd5 {
		t.Error("zstd levels 4 and 5 share a pool")
	}

	var buf1, buf2 bytes.Buffer

	// 1. Тест пулинга Deflate с кастомными уровнями
	crossLevelFlate := false
	reusedFlate := untilPoolHit(64, func() bool {
		w1 := newFlateWriterLevel(&buf1, 4).(*pooledFlateWriter)
		if w1.pool != flate4 {
			t.Error("a level 4 flate writer is not bound to the level 4 pool")
		}
		fw1 := w1.fw
		if err := w1.Close(); err != nil {
			t.Fatalf("failed to close the level 4 flate writer: %v", err)
		}

		// Получение нового писателя на том же уровне должно вернуть тот же экземпляр
		w2 := newFlateWriterLevel(&buf2, 4).(*pooledFlateWriter)
		hit := w2.fw == fw1
		if err := w2.Close(); err != nil {
			t.Fatalf("failed to close the second level 4 flate writer: %v", err)
		}

		// Получение писателя на другом уровне не должно переиспользовать прошлый объект
		w3 := newFlateWriterLevel(&buf2, 5).(*pooledFlateWriter)
		if w3.pool != flate5 {
			t.Error("a level 5 flate writer is not bound to the level 5 pool")
		}
		if w3.fw == fw1 {
			crossLevelFlate = true
		}
		if err := w3.Close(); err != nil {
			t.Fatalf("failed to close the level 5 flate writer: %v", err)
		}

		return hit
	})
	if !reusedFlate {
		t.Error("expected flate.Writer to be reused from the level-aware pool, but got different instances")
	}
	if crossLevelFlate {
		t.Error("did not expect flate.Writer from level 4 to be reused for level 5")
	}

	// 2. Тест пулинга ZSTD с кастомными уровнями
	crossLevelZstd := false
	reusedZstd := untilPoolHit(64, func() bool {
		zw1, err := newZstdWriterLevel(&buf1, 4)
		if err != nil {
			t.Fatalf("failed to create zstd writer: %v", err)
		}
		pzw1 := zw1.(*pooledZstdWriter)
		if pzw1.pool != zstd4 {
			t.Error("a level 4 zstd writer is not bound to the level 4 pool")
		}
		enc1 := pzw1.enc
		if err := pzw1.Close(); err != nil {
			t.Fatalf("failed to close the level 4 zstd writer: %v", err)
		}

		zw2, err := newZstdWriterLevel(&buf2, 4)
		if err != nil {
			t.Fatalf("failed to create zstd writer: %v", err)
		}
		pzw2 := zw2.(*pooledZstdWriter)
		hit := pzw2.enc == enc1
		if err := pzw2.Close(); err != nil {
			t.Fatalf("failed to close the second level 4 zstd writer: %v", err)
		}

		zw3, err := newZstdWriterLevel(&buf2, 5)
		if err != nil {
			t.Fatalf("failed to create zstd writer: %v", err)
		}
		pzw3 := zw3.(*pooledZstdWriter)
		if pzw3.pool != zstd5 {
			t.Error("a level 5 zstd writer is not bound to the level 5 pool")
		}
		if pzw3.enc == enc1 {
			crossLevelZstd = true
		}
		if err := pzw3.Close(); err != nil {
			t.Fatalf("failed to close the level 5 zstd writer: %v", err)
		}

		return hit
	})
	if !reusedZstd {
		t.Error("expected zstd.Encoder to be reused from the level-aware pool, but got different instances")
	}
	if crossLevelZstd {
		t.Error("did not expect zstd.Encoder from level 4 to be reused for level 5")
	}
}
func TestZstdLargeWindowDecompression(t *testing.T) {
	data := []byte("verification of zstd large window decoding capability")

	var compBuf bytes.Buffer
	enc, err := zstd.NewWriter(&compBuf)
	if err != nil {
		t.Fatalf("failed to create zstd encoder: %v", err)
	}
	mustWrite(t, enc, data)
	if err := enc.Close(); err != nil {
		t.Fatalf("failed to close zstd encoder: %v", err)
	}

	dec := newZstdReader(&compBuf)
	closeAt(t, dec)

	decompressed, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("failed to decompress data: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Errorf("content mismatch: got %q, want %q", string(decompressed), string(data))
	}
}
func TestZstd_CorruptedData(t *testing.T) {
	data := []byte("some data to compress and then corrupt it")
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w := mustCreateHeader(t, zw, &FileHeader{Name: "bad.zstd", Method: ZSTD})
	mustWrite(t, w, data)
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	raw := buf.Bytes()
	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("failed to read valid zip: %v", err)
	}

	// Find the exact offset of the start of the compressed data
	offset, err := zr.File[0].DataOffset()
	if err != nil {
		t.Fatalf("failed to get data offset: %v", err)
	}

	// Corrupt specifically the compressed data, without touching the headers
	for i := offset; i < offset+5 && i < int64(len(raw)); i++ {
		raw[i] = 0xAA
	}

	rc, err := zr.File[0].Open()
	if err != nil {
		// An error might occur right here during decompressor initialization
		return
	}
	closeAt(t, rc)

	_, err = io.ReadAll(rc)
	if err == nil {
		t.Error("expected decompression error for corrupted ZSTD stream, got nil")
	}
}
func TestZstd_WithDataDescriptor(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	fh := &FileHeader{
		Name:   "dd.zstd",
		Method: ZSTD,
	}
	fh.Flags |= 0x8 // Force enable Data Descriptor

	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, []byte("zstd data with descriptor"))
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("failed to create reader: %v", err)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("failed to open entry: %v", err)
	}
	closeAt(t, rc)
	data, _ := io.ReadAll(rc)

	if string(data) != "zstd data with descriptor" {
		t.Errorf("Data mismatch with DD: got %q", string(data))
	}
}
func TestSolidSeekIndex_RandomAccess(t *testing.T) {
	for _, continuous := range []bool{false, true} {
		chunkSize := uint32(1024)
		numChunks := 5
		var fullData bytes.Buffer
		for i := 0; i < numChunks; i++ {
			block := make([]byte, chunkSize)
			for j := 0; j < int(chunkSize); j++ {
				block[j] = byte('A' + ((i*int(chunkSize) + j) % 26))
			}
			fullData.Write(block)
		}

		buf := new(bytes.Buffer)
		zw := NewWriter(buf)

		payload := fullData.Bytes()
		fh := &FileHeader{
			Name:               "seekable.bin",
			Method:             Deflate,
			SeekChunkSize:      chunkSize,
			SeekContinuous:     continuous,
			UncompressedSize64: uint64(len(payload)),
		}

		w := mustCreateHeader(t, zw, fh)
		mustWrite(t, w, payload)
		if err := zw.Close(); err != nil {
			t.Fatalf("failed to close writer: %v", err)
		}

		zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}

		f := zr.File[0]
		rs, err := f.OpenSeekable()
		if err != nil {
			t.Fatalf("failed to open seekable (continuous=%v): %v", continuous, err)
		}

		targetOff := int64(chunkSize * 3)
		if _, err := rs.Seek(targetOff, io.SeekStart); err != nil {
			t.Fatalf("failed to seek to block 3 (continuous=%v): %v", continuous, err)
		}

		out := make([]byte, 10)
		if _, err := io.ReadFull(rs, out); err != nil {
			t.Fatalf("failed to read block 3 (continuous=%v): %v", continuous, err)
		}
		// For block 3 (start index 3072), 3072 % 26 = 4 ('E')
		if string(out) != "EFGHIJKLMN" {
			t.Errorf("seek to block 3 failed, got %q (continuous=%v)", string(out), continuous)
		}

		if _, err := rs.Seek(int64(chunkSize), io.SeekStart); err != nil {
			t.Fatalf("failed to seek to block 1 (continuous=%v): %v", continuous, err)
		}
		if _, err := io.ReadFull(rs, out); err != nil {
			t.Fatalf("failed to read block 1 (continuous=%v): %v", continuous, err)
		}
		// For block 1 (start index 1024), 1024 % 26 = 10 ('K')
		if string(out) != "KLMNOPQRST" {
			t.Errorf("seek to block 1 failed, got %q (continuous=%v)", string(out), continuous)
		}

		if _, err := rs.Seek(0, io.SeekEnd); err != nil {
			t.Fatalf("failed to seek to end (continuous=%v): %v", continuous, err)
		}
		n, err := rs.Read(out)
		if n != 0 || err != io.EOF {
			t.Errorf("expected EOF at end of file, got n=%d, err=%v", n, err)
		}
	}
}

func TestRegister_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when registering duplicate method")
		}
	}()
	// Method 8 (Deflate) is already registered in init()
	RegisterCompressor(Deflate, nil)
}

func TestDecompressor_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when registering duplicate decompressor")
		}
	}()
	RegisterDecompressor(Deflate, nil)
}

// TestPPMd_EntriesAreRefused: PPMd is a family of algorithms rather than one,
// and the variant ZIP uses is not the variant a decoder is available for here,
// so an entry compressed with it is turned away instead of being decoded into
// bytes nobody wrote. Nothing about the entry changes that answer, and the
// reason has to read as ErrAlgorithm, which is what a caller asks about when
// it wants to know whether an archive can be read at all.
func TestPPMd_EntriesAreRefused(t *testing.T) {
	// The two bytes a real entry carries here would say order 8 and a 50 MB
	// model. Nothing reads them any more.
	rc := newPPMdReader(bytes.NewReader([]byte{0x17, 0x03}), 1000)
	if rc == nil {
		t.Fatal("newPPMdReader handed back nothing at all")
	}
	closeAt(t, rc)
	if _, err := rc.Read(make([]byte, 10)); !errors.Is(err, ErrAlgorithm) {
		t.Errorf("reading a PPMd entry gave %v, want it refused as an algorithm this package cannot read", err)
	}
}

func TestLZMA_MemoryLimit(t *testing.T) {
	// Header: 2b version, 2b propSize (5), then 5b props.
	// props[1:5] is dictSize. Set it to 256MB (268435456 = 0x10000000)
	header := []byte{
		0x09, 0x00, // Version
		0x05, 0x00, // propSize
		0x5d,                   // props[0]
		0x00, 0x00, 0x00, 0x10, // dictSize 256MB
	}
	r := bytes.NewReader(header)
	rc := newLZMAReader(r)
	if rc == nil {
		t.Fatal("expected non-nil errorReader")
	}
	buf := make([]byte, 10)
	_, err := rc.Read(buf)
	if err == nil || !strings.Contains(err.Error(), "LZMA dictionary limit exceeded") {
		t.Errorf("expected LZMA memory limit error, got: %v", err)
	}
}
