package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// deflate64CovChunkReader hands out at most chunk bytes per Read, the way a
// socket does. The decoder then has to suspend inside a symbol and resume from
// the state it left behind, instead of seeing a whole block at once.
type deflate64CovChunkReader struct {
	data  []byte
	chunk int
}

func (r *deflate64CovChunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.chunk {
		n = r.chunk
	}
	if n > len(r.data) {
		n = len(r.data)
	}
	copy(p[:n], r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

// deflate64CovFailingReader fails every read, the way a broken pipe does.
type deflate64CovFailingReader struct {
	err error
}

func (r *deflate64CovFailingReader) Read([]byte) (int, error) {
	return 0, r.err
}

// TestDeflate64Cov_ReadShortcuts covers the two answers Read gives before it
// looks at the stream at all: a caller with no room gets nothing, and a caller
// that arrives after the stream has failed gets the same failure again.
func TestDeflate64Cov_ReadShortcuts(t *testing.T) {
	dr := decodeDeflate64(bytes.NewReader(nil))
	closeAt(t, dr)

	if n, err := dr.Read(nil); n != 0 || err != nil {
		t.Errorf("Read into an empty buffer returned (%d, %v), want (0, <nil>)", n, err)
	}

	// An empty stream is a truncated one: the first block header never
	// arrives, so the end of the input lands in the middle of a symbol.
	if _, err := dr.Read(make([]byte, 8)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reading an empty stream returned %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if n, err := dr.Read(make([]byte, 8)); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("reading again returned (%d, %v), want (0, %v)", n, err, io.ErrUnexpectedEOF)
	}
}

// TestDeflate64Cov_ReadReportsReaderError pins that a failure of the
// underlying stream reaches the caller as itself rather than as corrupt data,
// and that it is latched the same way.
func TestDeflate64Cov_ReadReportsReaderError(t *testing.T) {
	want := errors.New("the volume is no longer available")
	dr := decodeDeflate64(&deflate64CovFailingReader{err: want})
	closeAt(t, dr)

	if _, err := dr.Read(make([]byte, 8)); !errors.Is(err, want) {
		t.Fatalf("Read returned %v, want %v", err, want)
	}
	if _, err := dr.Read(make([]byte, 8)); !errors.Is(err, want) {
		t.Errorf("reading again returned %v, want %v", err, want)
	}
}

// TestDeflate64Cov_InputBufferBitLoading covers the accumulator refill: it
// pulls at most two bytes ahead, which is exactly what the widest field
// Deflate64 reads needs, and reports that it needs data rather than inventing
// bits when the input ends inside that field.
func TestDeflate64Cov_InputBufferBitLoading(t *testing.T) {
	if _, err := newInputBuffer(bitsBuffer{}, nil).getBits(1); !errors.Is(err, errDataNeeded) {
		t.Errorf("getBits on an empty buffer returned %v, want %v", err, errDataNeeded)
	}
	if _, err := newInputBuffer(bitsBuffer{}, []byte{0xFF}).getBits(16); !errors.Is(err, errDataNeeded) {
		t.Errorf("getBits(16) over a single byte returned %v, want %v", err, errDataNeeded)
	}

	// Two bytes cover the 16 extra bits of length code 285.
	in := newInputBuffer(bitsBuffer{}, []byte{0x34, 0x12})
	got, err := in.getBits(16)
	if err != nil {
		t.Fatalf("getBits(16) over two bytes failed: %v", err)
	}
	if got != 0x1234 {
		t.Errorf("getBits(16) = %#04x, want 0x1234", got)
	}
	if in.readBytes != 2 {
		t.Errorf("getBits(16) accounted for %d read bytes, want 2", in.readBytes)
	}

	// With a single byte left there is no 16 bit load to make, so the
	// accumulator takes the one byte and says so.
	one := newInputBuffer(bitsBuffer{}, []byte{0x5A})
	if got := one.tryLoad16Bits(); got != 0x5A {
		t.Errorf("tryLoad16Bits over a single byte = %#02x, want 0x5a", got)
	}
	if one.availableBits() != 8 {
		t.Errorf("tryLoad16Bits left %d bits available, want 8", one.availableBits())
	}
}

// TestDeflate64Cov_InputBufferCopyToLimits covers the two ways copyTo stops
// early: the destination fills up from the accumulator alone, and the input
// runs out before the destination is full.
func TestDeflate64Cov_InputBufferCopyToLimits(t *testing.T) {
	in := newInputBuffer(bitsBuffer{}, []byte{0x11, 0x22, 0x33})
	in.tryLoad16Bits()

	out := make([]byte, 2)
	if n := in.copyTo(out); n != 2 {
		t.Fatalf("copyTo copied %d bytes, want 2", n)
	}
	if want := []byte{0x11, 0x22}; !bytes.Equal(out, want) {
		t.Errorf("copyTo produced %x, want %x", out, want)
	}

	rest := make([]byte, 8)
	if n := in.copyTo(rest); n != 1 {
		t.Fatalf("copyTo of the remainder copied %d bytes, want 1", n)
	}
	if rest[0] != 0x33 {
		t.Errorf("copyTo of the remainder produced %#02x, want 0x33", rest[0])
	}
}

// TestDeflate64Cov_BuildHuffmanTreeDegenerate covers the two block counts a
// Huffman tree cannot be built from: no used symbol at all, and a single one,
// which gets a one bit code rather than a zero bit one.
func TestDeflate64Cov_BuildHuffmanTreeDegenerate(t *testing.T) {
	lengths := make([]byte, 8)
	buildHuffmanTree(make([]uint32, 8), 15, lengths)
	for sym, l := range lengths {
		if l != 0 {
			t.Errorf("symbol %d got length %d from an unused alphabet, want 0", sym, l)
		}
	}

	freqs := make([]uint32, 8)
	freqs[5] = 3
	buildHuffmanTree(freqs, 15, lengths)
	for sym, l := range lengths {
		want := byte(0)
		if sym == 5 {
			want = 1
		}
		if l != want {
			t.Errorf("symbol %d got length %d, want %d", sym, l, want)
		}
	}
}

// TestDeflate64Cov_BuildHuffmanTreeDepthLimit drives the depth correction.
// Fibonacci frequencies produce the deepest tree an alphabet of this size can
// have - every symbol pairs with the whole tail below it - so the plain tree
// runs past the limit and the lengths have to be redistributed.
func TestDeflate64Cov_BuildHuffmanTreeDepthLimit(t *testing.T) {
	freqs := []uint32{1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144}
	lengths := make([]byte, len(freqs))
	const maxDepth = 4

	buildHuffmanTree(freqs, maxDepth, lengths)

	kraft := 0
	for sym, l := range lengths {
		if l < 1 || int(l) > maxDepth {
			t.Errorf("symbol %d got length %d, want between 1 and %d", sym, l, maxDepth)
			continue
		}
		kraft += 1 << (maxDepth - int(l))
	}
	if kraft > 1<<maxDepth {
		t.Errorf("the corrected lengths oversubscribe the code: %d of %d", kraft, 1<<maxDepth)
	}

	// The lengths still have to describe a code a decoder can build a table
	// from, which is what the block header carries them for.
	if err := newHuffmanTreeInvalid().newInPlace(lengths); err != nil {
		t.Errorf("the corrected lengths describe no decodable code: %v", err)
	}
}

// TestDeflate64Cov_MatchFinderDropsFarMatch covers the distance cut off in
// front of the hash chain walk: the only earlier copy of the bytes at the
// current position sits further back than the window reaches, so it is not a
// match at all.
func TestDeflate64Cov_MatchFinderDropsFarMatch(t *testing.T) {
	const (
		gap    = 39000
		filler = 'z'
	)
	data := make([]byte, 40000)
	for i := range data {
		data[i] = filler
	}
	copy(data[:3], "abc")
	copy(data[gap:gap+3], "abc")

	mf := newMatchFinder(false, 64) // a 32 KB window, so 39000 bytes back is out of reach
	mf.reset(data)
	mf.skip(gap)

	if got := mf.findMatches(nil); len(got) != 0 {
		t.Errorf("a copy %d bytes back was reported as %v, want no match", gap, got)
	}
}

// TestDeflate64Cov_MatchFinderStopsAtSearchDepth covers the depth limit that
// keeps redundant data from turning the hash chain walk quadratic: with room
// for one candidate the second link in the chain is never examined.
func TestDeflate64Cov_MatchFinderStopsAtSearchDepth(t *testing.T) {
	data := []byte("abc1abc2abc3")

	mf := newMatchFinder(true, 1)
	mf.reset(data)
	mf.skip(8)

	got := mf.findMatches(nil)
	if len(got) != 1 {
		t.Fatalf("findMatches returned %v, want the single nearest candidate", got)
	}
	if got[0].length != 3 || got[0].distance != 4 {
		t.Errorf("findMatches returned length %d distance %d, want 3 and 4", got[0].length, got[0].distance)
	}
}

// TestDeflate64Cov_LengthSlotEdges covers the two slot lookups the encoder
// makes at the edge of their range: a run too short to be a match at all, and
// the lookahead limit when the best match so far does not reach the current
// position.
func TestDeflate64Cov_LengthSlotEdges(t *testing.T) {
	if got := getLenSlot(2); got != 0 {
		t.Errorf("getLenSlot(2) = %d, want 0", got)
	}
	if got := lenTestLimit(7, 4); got != 8 {
		t.Errorf("lenTestLimit(7, 4) = %d, want 8", got)
	}
	if got := lenTestLimit(4, 7); got != 8 {
		t.Errorf("lenTestLimit(4, 7) = %d, want 8", got)
	}
}

// TestDeflate64Cov_FlushEmptyNonFinalBlock pins that flushing with nothing
// buffered emits no block, so a Write that lands exactly on the block boundary
// does not put an empty block into the stream.
func TestDeflate64Cov_FlushEmptyNonFinalBlock(t *testing.T) {
	var buf bytes.Buffer
	dw, ok := newDeflate64Writer(&buf).(*deflate64Writer)
	if !ok {
		t.Fatal("newDeflate64Writer no longer returns a *deflate64Writer")
	}

	if err := dw.flushBlock(false); err != nil {
		t.Fatalf("flushing an empty block failed: %v", err)
	}
	if dw.w.nbits != 0 || dw.w.accum != 0 {
		t.Errorf("flushing an empty block emitted %d bits, want none", dw.w.nbits)
	}
}

// deflate64CovLevelBits is the width this file gives every symbol of the code
// length alphabet, so that symbol s is spelled by the number s.
const deflate64CovLevelBits = 5

// deflate64CovLevelCode is one entry of the code length sequence a dynamic
// block header carries: a symbol of the code length alphabet, plus the extra
// bits the repeat codes 16, 17 and 18 take after it.
type deflate64CovLevelCode struct {
	sym       byte
	extra     uint32
	extraBits uint32
}

// deflate64CovBuild collects a bit stream the way the encoder writes one.
func deflate64CovBuild(t *testing.T, write func(bw *bitWriter)) []byte {
	t.Helper()
	var buf bytes.Buffer
	bw := newBitWriter(&buf)
	write(bw)
	if err := bw.flushBits(); err != nil {
		t.Fatalf("assembling a stream failed: %v", err)
	}
	return buf.Bytes()
}

// deflate64CovDynamicHeader writes a dynamic block header describing numLit
// literal codes and numDist distance codes, with the code lengths spelled by
// the given sequence. Every code length symbol is given the same width, so the
// sequence can name any of them, including ones a real encoder would not use.
func deflate64CovDynamicHeader(bw *bitWriter, bfinal, numLit, numDist uint32, seq []deflate64CovLevelCode) {
	bw.writeBits(bfinal, kFinalBlockFieldSize)
	bw.writeBits(uint32(blockTypeDynamic), kBlockTypeFieldSize)
	bw.writeBits(numLit-kNumLitLenCodesMin, kNumLenCodesFieldSize)
	bw.writeBits(numDist-kNumDistCodesMin, kNumDistCodesFieldSize)
	bw.writeBits(numberOfCodeLengthTreeElements-kNumLevelCodesMin, kNumLevelCodesFieldSize)
	for i := 0; i < numberOfCodeLengthTreeElements; i++ {
		bw.writeBits(deflate64CovLevelBits, kLevelFieldSize)
	}
	for _, c := range seq {
		bw.writeBits(reverseBits(uint32(c.sym), deflate64CovLevelBits), deflate64CovLevelBits)
		if c.extraBits > 0 {
			bw.writeBits(c.extra, c.extraBits)
		}
	}
}

// deflate64CovLevels spells out code lengths one by one, without any of the
// runs a real encoder would fold into the repeat codes.
func deflate64CovLevels(parts ...[]byte) []deflate64CovLevelCode {
	var seq []deflate64CovLevelCode
	for _, part := range parts {
		for _, l := range part {
			seq = append(seq, deflate64CovLevelCode{sym: l})
		}
	}
	return seq
}

// deflate64CovSymbolWriter spells symbols with the canonical codes a set of
// code lengths defines, which is what the decoder rebuilds from the header.
type deflate64CovSymbolWriter struct {
	lengths []byte
	codes   []uint32
}

func deflate64CovSymbols(lengths []byte) *deflate64CovSymbolWriter {
	codes := make([]uint32, len(lengths))
	generateCodes(lengths, codes)
	return &deflate64CovSymbolWriter{lengths: lengths, codes: codes}
}

func (s *deflate64CovSymbolWriter) write(bw *bitWriter, sym int) {
	bw.writeBits(s.codes[sym], uint32(s.lengths[sym]))
}

// deflate64CovStored assembles stored blocks: a byte aligned header carrying
// the length and its one's complement, then the bytes themselves.
func deflate64CovStored(blocks ...[]byte) []byte {
	var out []byte
	for i, b := range blocks {
		var hdr [5]byte
		if i == len(blocks)-1 {
			hdr[0] = 1 // the last block, stored, and the rest of the byte is padding
		}
		// #nosec G115 -- every caller keeps a block inside the 65535 bytes the
		// length field of a stored block header can spell.
		size := uint16(len(b))
		binary.LittleEndian.PutUint16(hdr[1:3], size)
		binary.LittleEndian.PutUint16(hdr[3:5], ^size)
		out = append(out, hdr[:]...)
		out = append(out, b...)
	}
	return out
}

func deflate64CovDecode(stream []byte) ([]byte, error) {
	return io.ReadAll(decodeDeflate64(bytes.NewReader(stream)))
}

func deflate64CovDecodeInChunks(stream []byte, chunk int) ([]byte, error) {
	return io.ReadAll(decodeDeflate64(&deflate64CovChunkReader{data: stream, chunk: chunk}))
}

// deflate64CovSample is data with both faces a Deflate64 block has: bytes with
// no pattern to them, which spend the whole literal alphabet and so produce
// long Huffman codes, and a stretch that repeats an earlier one, which
// produces matches.
func deflate64CovSample() []byte {
	src := make([]byte, 1600)
	var word [4]byte
	x := uint32(1)
	for i := range src {
		x = x*1664525 + 1013904223
		binary.BigEndian.PutUint32(word[:], x)
		src[i] = word[0]
	}
	copy(src[800:], src[:400])
	copy(src[1200:], src[:400])
	return src
}

// deflate64CovStaticTail writes a block with the fixed Huffman codes that ends
// wherever the caller asks. wide sets how many of its literals are spelled
// with nine bits rather than eight, which is what decides where in a byte the
// block ends and so how many bits are left over for whatever follows it.
func deflate64CovStaticTail(t *testing.T, wide int, tail func(bw *bitWriter, syms *deflate64CovSymbolWriter)) []byte {
	t.Helper()
	staticLengths := getStaticLiteralTreeLength()
	syms := deflate64CovSymbols(staticLengths[:])

	return deflate64CovBuild(t, func(bw *bitWriter) {
		bw.writeBits(0, kFinalBlockFieldSize) // not the last block
		bw.writeBits(uint32(blockTypeStatic), kBlockTypeFieldSize)
		for i := 0; i < 4; i++ {
			syms.write(bw, 'a'+i) // eight bits each
		}
		for i := 0; i < wide; i++ {
			syms.write(bw, 144+i) // nine bits each
		}
		tail(bw, syms)
	})
}

func deflate64CovEncode(t *testing.T, src []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := newDeflate64Writer(&buf)
	mustWrite(t, enc, src)
	if err := enc.Close(); err != nil {
		t.Fatalf("encoding the sample failed: %v", err)
	}
	return buf.Bytes()
}

// TestDeflate64Cov_StaticBlock decodes a block written with the fixed Huffman
// codes RFC 1951 defines. The encoder in this package always emits dynamic
// blocks, so the fixed trees and the flat five bit distance field only ever
// turn up on streams other encoders wrote.
func TestDeflate64Cov_StaticBlock(t *testing.T) {
	const alphabet = "abcdefghijklmnop"
	src := make([]byte, 64)
	for i := range src {
		src[i] = alphabet[i%len(alphabet)]
	}
	want := append(append([]byte{}, src...), src[len(src)-8:]...)

	staticLengths := getStaticLiteralTreeLength()
	syms := deflate64CovSymbols(staticLengths[:])

	stream := deflate64CovBuild(t, func(bw *bitWriter) {
		bw.writeBits(1, kFinalBlockFieldSize)
		bw.writeBits(uint32(blockTypeStatic), kBlockTypeFieldSize)
		for _, b := range src {
			syms.write(bw, int(b))
		}
		syms.write(bw, 257+8-minMatch)     // a match eight bytes long
		bw.writeBits(reverseBits(5, 5), 5) // distance code 5 spans 7 and 8
		bw.writeBits(1, 1)                 // and its extra bit picks 8
		syms.write(bw, endOfBlockCode)
	})
	// Bytes past the end of the block, which it never reads. They leave the
	// decoder enough input in hand to take its fast path through the body.
	stream = append(stream, make([]byte, 16)...)

	got, err := deflate64CovDecode(stream)
	if err != nil {
		t.Fatalf("decoding a fixed code block failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decoded %q, want %q", got, want)
	}

	got, err = deflate64CovDecodeInChunks(stream, 1)
	if err != nil {
		t.Fatalf("decoding a fixed code block a byte at a time failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decoded %q a byte at a time, want %q", got, want)
	}
}

// TestDeflate64Cov_DynamicHeaderRejected covers the headers a dynamic block
// cannot be built from: the ones whose code lengths do not describe a tree,
// and the ones whose repeat codes run off the end of the alphabet they are
// describing.
func TestDeflate64Cov_DynamicHeaderRejected(t *testing.T) {
	lens := func(n int, set map[int]byte) []byte {
		out := make([]byte, n)
		for sym, l := range set {
			out[sym] = l
		}
		return out
	}
	// A literal alphabet whose lengths are fine, so the sequence gets as far
	// as the repeat code that follows it.
	plainLit := lens(257, map[int]byte{0: 1, endOfBlockCode: 1})

	cases := []struct {
		name     string
		numLit   uint32
		numDist  uint32
		sequence []deflate64CovLevelCode
	}{
		{
			name: "no code for the end of block symbol", numLit: 257, numDist: 1,
			sequence: deflate64CovLevels(lens(257, map[int]byte{0: 1, 1: 1}), lens(1, nil)),
		},
		{
			name: "literal code lengths that describe no tree", numLit: 257, numDist: 1,
			sequence: deflate64CovLevels(lens(257, map[int]byte{0: 1, 1: 1, endOfBlockCode: 10}), lens(1, nil)),
		},
		{
			name: "distance code lengths that describe no tree", numLit: 257, numDist: 32,
			sequence: deflate64CovLevels(plainLit, lens(32, map[int]byte{0: 1, 1: 1, 2: 10})),
		},
		{
			name: "a repeat with nothing in front of it", numLit: 257, numDist: 1,
			sequence: []deflate64CovLevelCode{{sym: 16, extraBits: 2}},
		},
		{
			name: "a repeat past the end of the alphabet", numLit: 257, numDist: 1,
			sequence: append(deflate64CovLevels(plainLit), deflate64CovLevelCode{sym: 16, extra: 3, extraBits: 2}),
		},
		{
			name: "a zero run past the end of the alphabet", numLit: 257, numDist: 1,
			sequence: append(deflate64CovLevels(plainLit), deflate64CovLevelCode{sym: 17, extra: 7, extraBits: 3}),
		},
		{
			name: "a long zero run past the end of the alphabet", numLit: 257, numDist: 1,
			sequence: append(deflate64CovLevels(plainLit), deflate64CovLevelCode{sym: 18, extraBits: 7}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := deflate64CovBuild(t, func(bw *bitWriter) {
				deflate64CovDynamicHeader(bw, 1, tc.numLit, tc.numDist, tc.sequence)
			})
			// Bytes past the header, so that a header cut short by its own
			// contents is not mistaken for one cut short by the stream.
			stream = append(stream, make([]byte, 16)...)

			if _, err := deflate64CovDecode(stream); !errors.Is(err, errDataError) {
				t.Errorf("decoding returned %v, want %v", err, errDataError)
			}
			if _, err := deflate64CovDecodeInChunks(stream, 1); !errors.Is(err, errDataError) {
				t.Errorf("decoding a byte at a time returned %v, want %v", err, errDataError)
			}
		})
	}
}

// TestDeflate64Cov_UndefinedLiteralCode covers a body that names a code its
// own header left out: the literal alphabet uses three of the four two bit
// codes, and the block asks for the fourth.
func TestDeflate64Cov_UndefinedLiteralCode(t *testing.T) {
	litLengths := make([]byte, 257)
	litLengths[0], litLengths[1], litLengths[endOfBlockCode] = 2, 2, 2
	distLengths := []byte{1}

	stream := deflate64CovBuild(t, func(bw *bitWriter) {
		deflate64CovDynamicHeader(bw, 1, 257, 1, deflate64CovLevels(litLengths, distLengths))
		bw.writeBits(reverseBits(3, 2), 2)
	})
	stream = append(stream, make([]byte, 16)...)

	if _, err := deflate64CovDecode(stream); !errors.Is(err, errDataError) {
		t.Errorf("decoding returned %v, want %v", err, errDataError)
	}
	if _, err := deflate64CovDecodeInChunks(stream, 1); !errors.Is(err, errDataError) {
		t.Errorf("decoding a byte at a time returned %v, want %v", err, errDataError)
	}
}

// TestDeflate64Cov_LengthCodeWithoutALength covers a body that names a literal
// symbol above the last length code, which no table in the format gives a
// length to.
func TestDeflate64Cov_LengthCodeWithoutALength(t *testing.T) {
	const strayCode = 286
	litLengths := make([]byte, maxLiteralTreeElements)
	litLengths[endOfBlockCode], litLengths[strayCode] = 1, 1
	distLengths := []byte{1}
	syms := deflate64CovSymbols(litLengths)

	stream := deflate64CovBuild(t, func(bw *bitWriter) {
		deflate64CovDynamicHeader(bw, 1, maxLiteralTreeElements, 1, deflate64CovLevels(litLengths, distLengths))
		syms.write(bw, strayCode)
	})
	stream = append(stream, make([]byte, 16)...)

	if _, err := deflate64CovDecode(stream); !errors.Is(err, errDataError) {
		t.Errorf("decoding returned %v, want %v", err, errDataError)
	}
	if _, err := deflate64CovDecodeInChunks(stream, 1); !errors.Is(err, errDataError) {
		t.Errorf("decoding a byte at a time returned %v, want %v", err, errDataError)
	}
}

// TestDeflate64Cov_TruncatedStream cuts a good stream at every byte and
// requires each piece to be reported as incomplete or corrupt. Every cut lands
// somewhere else in the header or the body, so between them they suspend the
// decoder at every field it reads.
func TestDeflate64Cov_TruncatedStream(t *testing.T) {
	stream := deflate64CovEncode(t, deflate64CovSample())

	for n := 0; n < len(stream); n++ {
		got, err := deflate64CovDecode(stream[:n])
		if err == nil {
			t.Fatalf("a stream cut to %d of %d bytes decoded %d bytes without complaint",
				n, len(stream), len(got))
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, errDataError) {
			t.Fatalf("a stream cut to %d of %d bytes returned %v", n, len(stream), err)
		}
	}
}

// TestDeflate64Cov_StreamArrivingInPieces decodes a good stream handed over a
// few bytes at a time, so that the decoder has to suspend inside a symbol and
// resume from the state it left behind.
func TestDeflate64Cov_StreamArrivingInPieces(t *testing.T) {
	src := deflate64CovSample()
	stream := deflate64CovEncode(t, src)

	for _, chunk := range []int{1, 3, 9} {
		got, err := deflate64CovDecodeInChunks(stream, chunk)
		if err != nil {
			t.Fatalf("decoding %d bytes at a time failed: %v", chunk, err)
		}
		if !bytes.Equal(got, src) {
			t.Errorf("decoding %d bytes at a time produced %d bytes, want %d", chunk, len(got), len(src))
		}
	}
}

// TestDeflate64Cov_StoredBlockLimits covers the two ways a stored block runs
// out of input: handed over a byte at a time it has to resume between the
// header bytes, and cut short it has to stop at what arrived.
func TestDeflate64Cov_StoredBlockLimits(t *testing.T) {
	payload := []byte("stored bytes carry no codes, only themselves")
	stream := deflate64CovStored(payload)

	got, err := deflate64CovDecodeInChunks(stream, 1)
	if err != nil {
		t.Fatalf("decoding a stored block a byte at a time failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("decoded %q, want %q", got, payload)
	}

	const missing = 10
	got, err = deflate64CovDecode(stream[:len(stream)-missing])
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("decoding a stored block cut short returned %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if want := payload[:len(payload)-missing]; !bytes.Equal(got, want) {
		t.Errorf("a stored block cut short yielded %q, want %q", got, want)
	}
}

// TestDeflate64Cov_BlockEndsInsideAByte covers what is left of a byte when a
// block ends part way through it. Nine bit literals move the end of the block
// around inside the last byte, so between them these streams leave the next
// block header every count of bits it can be left, and each one has to be
// reported as a stream that stops too early rather than decoded from padding.
func TestDeflate64Cov_BlockEndsInsideAByte(t *testing.T) {
	shapes := []struct {
		name string
		tail func(bw *bitWriter, syms *deflate64CovSymbolWriter)
	}{
		{"nothing after the block", func(bw *bitWriter, syms *deflate64CovSymbolWriter) {
			syms.write(bw, endOfBlockCode)
		}},
		{"the start of a dynamic block header", func(bw *bitWriter, syms *deflate64CovSymbolWriter) {
			syms.write(bw, endOfBlockCode)
			bw.writeBits(0, kFinalBlockFieldSize)
			bw.writeBits(uint32(blockTypeDynamic), kBlockTypeFieldSize)
		}},
		{"a match with no distance after it", func(bw *bitWriter, syms *deflate64CovSymbolWriter) {
			syms.write(bw, 257) // the shortest match, which takes no extra bits
		}},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			for wide := 0; wide < 8; wide++ {
				stream := deflate64CovStaticTail(t, wide, shape.tail)
				if _, err := deflate64CovDecode(stream); !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("with %d nine bit literals the stream returned %v, want %v",
						wide, err, io.ErrUnexpectedEOF)
				}
			}
		})
	}
}

// TestDeflate64Cov_CodeLengthSequenceRunsOut covers a header that stops
// between a repeat code and the count that belongs with it. The number of code
// lengths in front of the repeat moves it around inside the last byte, so
// between them these headers leave every count of bits the repeat codes need.
func TestDeflate64Cov_CodeLengthSequenceRunsOut(t *testing.T) {
	for _, repeat := range []byte{16, 17, 18} {
		for shift := 0; shift < 8; shift++ {
			seq := []deflate64CovLevelCode{{sym: 1}}
			for i := 0; i < shift; i++ {
				seq = append(seq, deflate64CovLevelCode{sym: 0})
			}
			// The repeat code itself, with the stream ending where its count
			// would be.
			seq = append(seq, deflate64CovLevelCode{sym: repeat})

			stream := deflate64CovBuild(t, func(bw *bitWriter) {
				deflate64CovDynamicHeader(bw, 1, 257, 1, seq)
			})
			if _, err := deflate64CovDecode(stream); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("code %d after %d lengths returned %v, want %v",
					repeat, shift+1, err, io.ErrUnexpectedEOF)
			}
		}
	}
}

// TestDeflate64Cov_UndefinedDistanceCode covers a body that names a distance
// code its own header left out: the distance alphabet uses three of the four
// two bit codes, and the block asks for the fourth after a match length.
func TestDeflate64Cov_UndefinedDistanceCode(t *testing.T) {
	const shortestMatch = 257
	litLengths := make([]byte, shortestMatch+1)
	litLengths[endOfBlockCode], litLengths[shortestMatch] = 1, 1
	distLengths := []byte{2, 2, 2, 0}
	syms := deflate64CovSymbols(litLengths)

	stream := deflate64CovBuild(t, func(bw *bitWriter) {
		deflate64CovDynamicHeader(bw, 1, shortestMatch+1, 4, deflate64CovLevels(litLengths, distLengths))
		syms.write(bw, shortestMatch)
		bw.writeBits(reverseBits(3, 2), 2)
	})
	stream = append(stream, make([]byte, 16)...)

	if _, err := deflate64CovDecode(stream); !errors.Is(err, errDataError) {
		t.Errorf("decoding returned %v, want %v", err, errDataError)
	}
	if _, err := deflate64CovDecodeInChunks(stream, 1); !errors.Is(err, errDataError) {
		t.Errorf("decoding a byte at a time returned %v, want %v", err, errDataError)
	}
}

// TestDeflate64Cov_DistanceCodeOutsideTheTables covers the bound the fast path
// keeps on a distance code. A block header cannot name more than
// maxDistTreeElements distance codes, so the tree here is one no header can
// describe, and the guard is what stands between such a tree and a lookup past
// the end of the distance tables.
func TestDeflate64Cov_DistanceCodeOutsideTheTables(t *testing.T) {
	const shortestMatch = 257
	litLengths := make([]byte, shortestMatch+1)
	litLengths[endOfBlockCode], litLengths[shortestMatch] = 1, 1

	distLengths := make([]byte, maxDistTreeElements+8)
	distLengths[maxDistTreeElements], distLengths[maxDistTreeElements+1] = 1, 1

	im := newInflaterManaged()
	im.blockType = blockTypeDynamic
	im.state = stateDecodeTop
	im.literalLengthTree = newHuffmanTreeInvalid()
	if err := im.literalLengthTree.newInPlace(litLengths); err != nil {
		t.Fatalf("building the literal tree failed: %v", err)
	}
	im.distanceTree = newHuffmanTreeInvalid()
	if err := im.distanceTree.newInPlace(distLengths); err != nil {
		t.Fatalf("building the distance tree failed: %v", err)
	}

	var eob bool
	body := bytes.Repeat([]byte{0xFF}, 16)
	if err := im.decodeBlock(newInputBuffer(bitsBuffer{}, body), &eob); !errors.Is(err, errDataError) {
		t.Errorf("a distance code past the tables returned %v, want %v", err, errDataError)
	}
}

// deflate64CovDriveInflater decodes a stream without the reader in front of
// it, so the test decides when the history window is emptied: it is emptied
// once the free space in it is down to drainBelow bytes. A reader takes
// everything out after every step, which is drainBelow = windowSize; leaving
// it fuller than that is how the window is seen at its edges.
func deflate64CovDriveInflater(t *testing.T, stream []byte, drainBelow int, onlyWhenStuck bool) []byte {
	t.Helper()
	im := newInflaterManaged()
	in := newInputBuffer(bitsBuffer{}, stream)
	buf := make([]byte, windowSize)
	var out []byte

	for step := 0; step < 400; step++ {
		before := im.output.availableBytes()
		if err := im.decode(in); err != nil {
			t.Fatalf("decoding failed at step %d: %v", step, err)
		}
		stuck := im.output.availableBytes() == before
		if im.state == stateDone || (im.output.freeBytes() <= drainBelow && (stuck || !onlyWhenStuck)) {
			n := im.output.copyTo(buf)
			out = append(out, buf[:n]...)
		}
		if im.state == stateDone {
			return out
		}
	}
	t.Fatal("the decoder stopped making progress")
	return nil
}

// TestDeflate64Cov_WindowWrapAndFill covers the history window at its two
// edges. Blocks of stored bytes are the shortest way to push a lot of output
// through it: with the window emptied after every block the copy wraps past
// its end, and with the window left to fill the copy is cut short by the space
// left and the block suspends until there is room.
func TestDeflate64Cov_WindowWrapAndFill(t *testing.T) {
	const blockLen = 65535
	blocks := make([][]byte, 4)
	want := make([]byte, 0, len(blocks)*blockLen)
	var word [4]byte
	x := uint32(1)
	for i := range blocks {
		b := make([]byte, blockLen)
		for j := range b {
			x = x*1664525 + 1013904223
			binary.BigEndian.PutUint32(word[:], x)
			b[j] = word[0]
		}
		blocks[i] = b
		want = append(want, b...)
	}
	stream := deflate64CovStored(blocks...)

	// Emptied after every block the copy wraps past the end of the window;
	// left to fill it is cut short by the space left, and the block suspends
	// until there is room again.
	for _, drainBelow := range []int{windowSize, 0} {
		got := deflate64CovDriveInflater(t, stream, drainBelow, false)
		if !bytes.Equal(got, want) {
			t.Errorf("decoding stored blocks, emptying the window at %d free bytes, produced %d bytes, want %d",
				drainBelow, len(got), len(want))
		}
	}

	// A compressed block stops short of filling the window, because the
	// decoder keeps room for one longest match, so a reader that takes nothing
	// out leaves it with a block to decode and nowhere to put it.
	src := bytes.Repeat([]byte("compressed bytes that repeat and repeat. "), 3500)
	got := deflate64CovDriveInflater(t, deflate64CovEncode(t, src), tableLookupLengthMax-1, true)
	if !bytes.Equal(got, src) {
		t.Errorf("decoding compressed blocks produced %d bytes, want %d", len(got), len(src))
	}
}

// TestDeflate64Cov_InflaterStateGuards covers the answers the block decoder
// gives when it is asked to carry on from a state that is not a block: the
// stream that is already finished, the one that already failed, and a block
// type the format reserves.
func TestDeflate64Cov_InflaterStateGuards(t *testing.T) {
	input := func() *inputBuffer { return newInputBuffer(bitsBuffer{}, []byte{0xFF, 0xFF, 0xFF, 0xFF}) }

	im := newInflaterManaged()
	im.state = stateDone
	if err := im.decode(input()); err != nil {
		t.Errorf("decoding past the last block returned %v, want <nil>", err)
	}

	im = newInflaterManaged()
	im.state = stateDataErrored
	if err := im.decode(input()); !errors.Is(err, errDataError) {
		t.Errorf("decoding after a failure returned %v, want %v", err, errDataError)
	}

	// Block type 3 is reserved, both where the header names it and later, if
	// the stream carries on after being told so.
	im = newInflaterManaged()
	if err := im.decode(newInputBuffer(bitsBuffer{}, []byte{0x07})); !errors.Is(err, errDataError) {
		t.Errorf("a reserved block type returned %v, want %v", err, errDataError)
	}
	im = newInflaterManaged()
	im.blockType = 3
	im.state = stateDecodeTop
	if err := im.decode(input()); !errors.Is(err, errDataError) {
		t.Errorf("carrying on inside a reserved block type returned %v, want %v", err, errDataError)
	}

	// A reader whose decoder has failed repeats the failure without reading.
	dr := &deflate64Reader{r: bytes.NewReader(nil), im: newInflaterManaged(), inBuf: make([]byte, 64)}
	dr.im.state = stateDataErrored
	if _, err := dr.Read(make([]byte, 4)); !errors.Is(err, errDataError) {
		t.Errorf("reading from a failed decoder returned %v, want %v", err, errDataError)
	}
}

// TestDeflate64Cov_OutOfRangeCodes covers the two table lookups the block
// decoder guards: a length code and a distance code past the end of the tables
// that give them their base value.
func TestDeflate64Cov_OutOfRangeCodes(t *testing.T) {
	var eob bool
	input := func() *inputBuffer { return newInputBuffer(bitsBuffer{}, []byte{0xFF, 0xFF, 0xFF, 0xFF}) }

	im := newInflaterManaged()
	im.state = stateHaveInitialLength
	im.length = len(lengthBase)
	im.extraBits = 1
	if err := im.decodeBlock(input(), &eob); !errors.Is(err, errDataError) {
		t.Errorf("a length code past the table returned %v, want %v", err, errDataError)
	}

	im = newInflaterManaged()
	im.state = stateHaveDistCode
	im.distanceCode = maxDistTreeElements
	if err := im.decodeBlock(input(), &eob); !errors.Is(err, errDataError) {
		t.Errorf("a distance code past the table returned %v, want %v", err, errDataError)
	}
}

// TestDeflate64Cov_UnknownStatePanics pins that the three block decoders stop
// loudly rather than spinning when they are handed a state belonging to
// another block type.
func TestDeflate64Cov_UnknownStatePanics(t *testing.T) {
	cases := []struct {
		name  string
		state inflaterState
		call  func(im *inflaterManaged, in *inputBuffer) error
	}{
		{"stored", stateDecodeTop, func(im *inflaterManaged, in *inputBuffer) error {
			var eob bool
			return im.decodeUncompressedBlock(in, &eob)
		}},
		{"compressed", stateUncompressedByte1, func(im *inflaterManaged, in *inputBuffer) error {
			var eob bool
			return im.decodeBlock(in, &eob)
		}},
		{"dynamic header", stateDecodeTop, func(im *inflaterManaged, in *inputBuffer) error {
			return im.decodeDynamicBlockHeader(in)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("a state from another block type was accepted, want a panic")
				}
			}()
			im := newInflaterManaged()
			im.state = tc.state
			_ = tc.call(im, newInputBuffer(bitsBuffer{}, []byte{0xFF, 0xFF, 0xFF, 0xFF}))
		})
	}
}
