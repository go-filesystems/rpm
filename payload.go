// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// The five values rpm writes into PAYLOADCOMPRESSOR.
const (
	CompressorNone  = "none"
	CompressorGzip  = "gzip"
	CompressorBzip2 = "bzip2"
	CompressorXz    = "xz"
	CompressorZstd  = "zstd"
)

// PayloadFormatCpio is the only PAYLOADFORMAT this reader opens.
const PayloadFormatCpio = "cpio"

// payloadCompressor is the compressor named by the main header, with rpm's own
// default for a package that names none.
//
// ⛔ A MISSING TAG MEANS GZIP, NOT "none". rpm gained PAYLOADCOMPRESSOR in 4.0
// (2000); before that every payload was gzip and nothing said so. Defaulting to
// "none" instead turns each of those packages into a cpio parse failure on the
// first two bytes of a deflate stream, and the error names cpio -- so the
// diagnosis lands three layers away from the missing tag that caused it.
//
// The el5 witness in testdata DOES carry the tag, so this default is reasoned
// from rpm's source (rpmfi.c's rpmfiNew) rather than measured here. That is
// stated because it is the one rule in this file no witness in the repository
// exercises against a real package; craftedNoCompressorTag in the tests
// exercises it against a package of this reader's own making, which proves the
// branch runs and not that a real 1999 package is read correctly.
func payloadCompressor(h *Header) string {
	if !h.Has(TagPayloadCompressor) {
		return CompressorGzip
	}
	return h.String(TagPayloadCompressor)
}

// newZstdReader builds the zstd decoder, and is a VARIABLE for one reason: the
// error it returns cannot be reached by any input.
//
// ⛔ zstd.NewReader fails only when one of its options fails to apply, and this
// call passes no options -- so `if err != nil` below is dead against every
// possible package, and the 100% coverage gate this repository enforces cannot be
// met by feeding it bytes. Deleting the check, or discarding the error with `_`,
// would satisfy the gate by removing the handling instead of exercising it.
//
// ⚠ WHAT THE TEST THAT OVERRIDES THIS PROVES, AND WHAT IT DOES NOT. Injecting a
// failure here proves decompressPayload PROPAGATES the error and wraps it with
// the compressor's name. It does not prove zstd ever fails that way, and no
// witness in this repository can, because the library does not.
var newZstdReader = func(r io.Reader) (io.ReadCloser, error) {
	d, err := zstd.NewReader(r)
	if err != nil {
		return nil, err
	}
	// IOReadCloser's Close releases the decoder's goroutines, which a bare
	// io.Reader wrapper would leak once per package opened.
	return d.IOReadCloser(), nil
}

// decompressPayload reads the whole payload and returns the cpio archive.
//
// ⛔ IT MATERIALISES THE WHOLE THING IN MEMORY, and that is a property of the
// format rather than a shortcut. An RPM payload is ONE compressed stream: the
// bytes of the last file cannot be reached without decoding every byte before
// them, so there is no byte range this could answer lazily. Holding the result
// is what lets the filesystem below answer ReadAt at all -- which is why this
// driver can implement filesystem.Opener honestly, where a driver that streamed
// would have to refuse it.
//
// The cost is the INSTALLED size of the package, not its download size. A caller
// opening an arbitrary .rpm should budget for that; Metadata reads the headers
// alone and never calls this.
func decompressPayload(r io.ReaderAt, off, n int64, compressor string) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("rpm: payload at %d has negative length %d: %w", off, n, ErrCorrupt)
	}
	sr := io.NewSectionReader(r, off, n)
	var zr io.Reader
	switch compressor {
	case CompressorNone:
		zr = sr
	case CompressorGzip:
		g, err := gzip.NewReader(sr)
		if err != nil {
			return nil, fmt.Errorf("rpm: gzip payload: %w", err)
		}
		defer g.Close() //nolint:errcheck // read side; Close only checks the trailer
		zr = g
	case CompressorBzip2:
		zr = bzip2.NewReader(sr)
	case CompressorXz:
		x, err := xz.NewReader(sr)
		if err != nil {
			return nil, fmt.Errorf("rpm: xz payload: %w", err)
		}
		zr = x
	case CompressorZstd:
		d, err := newZstdReader(sr)
		if err != nil {
			return nil, fmt.Errorf("rpm: zstd payload: %w", err)
		}
		defer d.Close() //nolint:errcheck // read side
		zr = d
	default:
		return nil, fmt.Errorf("rpm: payload compressor %q: %w", compressor, ErrUnsupported)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, zr); err != nil {
		return nil, fmt.Errorf("rpm: decompressing the %s payload: %w", compressor, err)
	}
	return buf.Bytes(), nil
}
