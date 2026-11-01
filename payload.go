// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"github.com/go-compressions/xz"
	"github.com/klauspost/compress/zstd"
)

// The five values rpm writes into PAYLOADCOMPRESSOR.
const (
	CompressorNone  = "none"
	CompressorGzip  = "gzip"
	CompressorBzip2 = "bzip2"
	CompressorXz    = "xz"
	CompressorZstd  = "zstd"
)

// The ceilings. An RPM is untrusted input and a payload is the one thing in it that
// is compressed, so what it inflates to is the file's choice unless these say
// otherwise. Each is a number the format does not fix; the reference each was taken
// from is named where it is used.
const (
	// DefaultMaxPayload is what Open allows a payload to inflate to: 1 GiB, the
	// installed size of a very large package. OpenLimit takes another.
	DefaultMaxPayload = 1 << 30
	// MaxDecoderWindow bounds the memory a compressor may ask for up front: a zstd
	// window or an xz LZMA2 dictionary. 128 MiB is libzstd's default limit.
	MaxDecoderWindow = 128 << 20
	// MaxEntries bounds the entries of the payload, real and synthesised parent
	// directories together. A real package has hundreds of thousands at most.
	MaxEntries = 1 << 22
	// MaxPathLength bounds one entry's path: Linux's PATH_MAX (limits.h), which is
	// also what the kernel's initramfs unpacker refuses beyond (init/initramfs.c).
	MaxPathLength = 4096
)

// maxEntries is MaxEntries, as a variable only so that a test can lower it: a test
// of the ceiling that needed four million entries would be a test nobody runs.
var maxEntries = MaxEntries

// xzMaxDictionary is MaxDecoderWindow, as a variable only so that a test can lower it:
// proving the xz ceiling exact at 128 MiB would need 128 MiB of output.
var xzMaxDictionary = MaxDecoderWindow

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
	// ⛔ THE WINDOW IS CAPPED. The library's default is 512 MiB and it allocates the
	// window up front: measured, a 9-byte frame declaring one made NewReader plus a
	// read allocate 537 151 024 bytes. 128 MiB is libzstd's own default limit
	// (zstd.h, ZSTD_WINDOWLOG_LIMIT_DEFAULT = 27), so no frame the reference decoder
	// accepts by default is refused here.
	d, err := zstd.NewReader(r, zstd.WithDecoderMaxWindow(MaxDecoderWindow))
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
//
// ⛔ THE OUTPUT IS BOUNDED BY maxOut, which Open sets to DefaultMaxPayload. Without
// it a few hundred kilobytes of gzip (1000:1) or xz and zstd (far more) inflate to
// whatever the file chooses: measured, a 526 630-byte package holding a 256 MiB
// file made Open allocate 1 073 799 504 bytes. The cap is checked on the bytes that
// actually arrive, one over the limit being enough to refuse, so nothing past
// maxOut+1 is ever held; bytes.Buffer's doubling can still touch twice that.
func decompressPayload(r io.ReaderAt, off, n int64, compressor string, maxOut int64) ([]byte, error) {
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
		// ⛔ THE DICTIONARY FOLLOWS THE OUTPUT. go-compressions/xz grows the LZMA2
		// window with the data decoded and refuses, with xz.ErrTooLarge and before
		// allocating, a window that would pass MaxDecoderWindow -- in any block of
		// any stream. (ulikunitz/xz allocated the dictionary a Block Header
		// declared, up to 4 GiB, and had no ceiling.)
		x, err := xz.ReaderConfig{MaxDictionary: xzMaxDictionary}.NewReader(sr)
		if err != nil {
			return nil, xzError(err)
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
	// One byte over the ceiling is enough to know it was crossed. A ceiling no int
	// can hold (maxOut near MaxInt64, or over 2 GiB on a 32-bit target) is clamped
	// to the largest slice Go can make, so bytes.Buffer never panics on its own.
	limit := min(maxOut, int64(maxInt)-1)
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(zr, limit+1)); err != nil {
		if errors.Is(err, zstd.ErrWindowSizeExceeded) {
			return nil, fmt.Errorf("rpm: the zstd payload wants a window over %d bytes: %w: %w",
				MaxDecoderWindow, ErrTooLarge, err)
		}
		if compressor == CompressorXz {
			return nil, xzError(err)
		}
		return nil, fmt.Errorf("rpm: decompressing the %s payload: %w", compressor, err)
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("rpm: the %s payload inflates past %d bytes: %w",
			compressor, limit, ErrTooLarge)
	}
	return buf.Bytes(), nil
}

// xzError names an xz failure, keeping the refusal callers have always seen for a
// dictionary over MaxDecoderWindow: ErrTooLarge, wrapping the library's error.
func xzError(err error) error {
	if errors.Is(err, xz.ErrTooLarge) {
		return fmt.Errorf("rpm: the xz payload wants a dictionary over %d bytes: %w: %w",
			MaxDecoderWindow, ErrTooLarge, err)
	}
	return fmt.Errorf("rpm: xz payload: %w", err)
}

// maxInt is the largest int, which is what bytes.Buffer can hold.
const maxInt = int(^uint(0) >> 1)
