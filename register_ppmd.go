package zip

import "io"

// newPPMdReader answers a method 98 entry. Nothing here decodes one: see
// errPPMdVariant for why an entry compressed with PPMd is turned away rather
// than read.
func newPPMdReader(r io.Reader, size uint64) io.ReadCloser {
	return errorReader{errPPMdVariant}
}
