package zip

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestU64ToI64(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   uint64
		want int64
	}{
		{"zero", 0, 0},
		{"one", 1, 1},
		{"max", math.MaxInt64, math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := u64toi64(tc.in)
			if err != nil {
				t.Fatalf("u64toi64(%d) = %v, want no error", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("u64toi64(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestU64ToI64RejectsWhatDoesNotFit(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   uint64
	}{
		{"one past MaxInt64", uint64(math.MaxInt64) + 1},
		{"all bits set", math.MaxUint64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := u64toi64(tc.in)
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("u64toi64(%d) = %v, want ErrFormat", tc.in, err)
			}
			if got != 0 {
				t.Fatalf("u64toi64(%d) returned %d alongside the error, want 0", tc.in, got)
			}
			if !strings.Contains(err.Error(), "does not fit") {
				t.Fatalf("error %q does not say what is wrong", err)
			}
		})
	}
}

func TestFitUint16(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   int
	}{
		{"zero", 0},
		{"one", 1},
		{"max", uint16max},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fitUint16(tc.in, "name")
			if err != nil {
				t.Fatalf("fitUint16(%d) = %v, want no error", tc.in, err)
			}
			if int(got) != tc.in {
				t.Fatalf("fitUint16(%d) = %d, want the same value back", tc.in, got)
			}
		})
	}
}

func TestFitUint16RejectsWhatDoesNotFit(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   int
	}{
		{"one past the field", uint16max + 1},
		{"negative", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fitUint16(tc.in, "file name")
			if err == nil {
				t.Fatalf("fitUint16(%d) returned no error", tc.in)
			}
			if got != 0 {
				t.Fatalf("fitUint16(%d) returned %d alongside the error, want 0", tc.in, got)
			}
			if !strings.Contains(err.Error(), "file name") {
				t.Fatalf("error %q does not name the field", err)
			}
		})
	}
}
