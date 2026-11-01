// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// xzMagic opens every .xz stream (xz-file-format.txt, 2.1.1.1).
var xzMagic = []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}

// lzma2FilterID is the filter ID of LZMA2 (xz-file-format.txt, 5.3.1).
const lzma2FilterID = 0x21

// checkXZDictionary refuses an xz stream whose first block declares an LZMA2
// dictionary larger than MaxDecoderWindow, before ulikunitz/xz allocates it.
//
// ⛔ THE LIBRARY HAS NO CEILING. xz.ReaderConfig.DictCap is a floor: lzmafilter.go
// raises it to whatever the Block Header declares, up to 4 GiB, and the decoder
// allocates that much at once. Measured: a 64-byte stream declaring a 512 MiB
// dictionary made xz.NewReader plus a read allocate 536 929 200 bytes. libzstd
// refuses a window over 128 MiB by default (zstd.h, ZSTD_WINDOWLOG_LIMIT_DEFAULT);
// this is the same ceiling for xz, applied by reading the one field that decides
// it (xz-file-format.txt, 3.1 Block Header and 5.3.1 LZMA2).
//
// ⚠ IT LOOKS AT THE FIRST BLOCK OF THE FIRST STREAM ONLY. The Block Header of
// block 1 sits at a fixed offset (12); where block 2 begins is known only by
// decoding block 1, and an Index that says otherwise is the file's to forge. A
// stream whose first block is benign and whose second declares a huge dictionary is
// NOT caught, and neither is a second stream. xz utilities write one filter chain
// for every block of a stream, so this covers every package they produce; it does
// not cover a hostile one. Closing it needs a ceiling inside the decoder (a
// ulikunitz/xz option) or a decoder of our own; it is recorded as open.
//
// A malformed header is not this function's to report: it returns nil and the
// library names the fault. It refuses only what it positively identified.
func checkXZDictionary(r io.ReaderAt) error {
	const streamHeader = 12
	var buf [streamHeader + 1024]byte
	n, _ := r.ReadAt(buf[:], 0) // a short read is a short stream: the library reports it
	b := buf[:n]
	if len(b) <= streamHeader || !bytes.HasPrefix(b, xzMagic) {
		return nil
	}
	hdr := b[streamHeader:]
	size := (int(hdr[0]) + 1) * 4 // 3.1.1: real_header_size = (encoded + 1) * 4
	if hdr[0] == 0 || size > len(hdr) {
		return nil // 0 is the Index Indicator: a stream with no block at all
	}
	flags := hdr[1]
	p := hdr[2 : size-4] // between the flags and the CRC32
	for _, present := range []bool{flags&0x40 != 0, flags&0x80 != 0} {
		if !present {
			continue
		}
		_, k := binary.Uvarint(p) // Compressed Size, then Uncompressed Size
		if k <= 0 {
			return nil
		}
		p = p[k:]
	}
	for range int(flags&3) + 1 {
		id, k := binary.Uvarint(p)
		if k <= 0 {
			return nil
		}
		p = p[k:]
		plen, k := binary.Uvarint(p)
		if k <= 0 || plen > uint64(len(p)-k) {
			return nil
		}
		props := p[k : k+int(plen)]
		p = p[k+int(plen):]
		if id != lzma2FilterID || len(props) != 1 {
			continue
		}
		bits := props[0] & 0x3F
		if bits > 40 {
			return nil // 5.3.1: bigger than 4 GiB; the library refuses it
		}
		// 5.3.1: one-bit mantissa, five-bit exponent.
		dict := uint64(2|bits&1) << (bits/2 + 11)
		if dict > MaxDecoderWindow {
			return fmt.Errorf("rpm: xz dictionary of %d bytes is over the %d ceiling: %w",
				dict, MaxDecoderWindow, ErrTooLarge)
		}
	}
	return nil
}
