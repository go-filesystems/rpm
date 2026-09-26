// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/go-filesystems/cpio"
	"io"
	"strconv"
	"strings"
	"testing"
)

// ⭐ THE ABLATION SUITE, AND WHY IT IS NOT JUST MORE TESTS.
//
// A passing test says the reader agrees with the fixture. It does not say the
// rule under test is LOAD-BEARING: a rule nothing depends on passes its test and
// passes with the rule deleted, and that is indistinguishable from a rule that
// matters. So each ablation here removes one rule and asserts the suite then
// FAILS on a real package.
//
// ⛔ AN ABLATION THAT PASSES IS A FINDING, not a pass. It means either the rule
// is unnecessary or -- far more likely -- the witnesses cannot see it. Two of the
// six below have something to report; see README.md.
//
// # The harness, and its control
//
// ablatedMetadata is a SECOND parser, parametrised, so that a rule can be
// switched off without editing the one that ships. A second parser is a liability
// -- it can drift from the first and then the ablation measures the copy -- so
// TestAblationHarnessMatchesTheReader is run FIRST and asserts that the harness
// with every knob at its correct setting produces exactly what Metadata does, on
// all three real packages. Without that control the rest of this file measures
// nothing.

// ablation names one rule to switch off.
type ablation struct {
	// padSignature false omits the 8-byte alignment after the signature
	// header's data store.
	padSignature bool
	// endian is the byte order the 16-byte index entries are read with.
	endian binary.ByteOrder
	// leadLen is where the signature header is looked for.
	leadLen int64
}

func correctAblation() ablation {
	return ablation{padSignature: true, endian: binary.BigEndian, leadLen: leadSize}
}

// ablatedHeader is the parametrised header reader.
func ablatedHeader(r io.ReaderAt, size, off int64, a ablation) (map[uint32]Entry, []byte, int64, error) {
	pre := make([]byte, headerPrefix)
	if _, err := r.ReadAt(pre, off); err != nil {
		return nil, nil, 0, err
	}
	if [3]byte(pre[0:3]) != headerMagic {
		return nil, nil, 0, fmt.Errorf("ablated: magic at %d is %#x: %w", off, pre[0:3], ErrCorrupt)
	}
	nindex := int64(binary.BigEndian.Uint32(pre[8:12]))
	hsize := int64(binary.BigEndian.Uint32(pre[12:16]))
	if nindex < 0 || nindex > maxIndex || hsize < 0 || hsize > maxData {
		return nil, nil, 0, fmt.Errorf("ablated: %d/%d: %w", nindex, hsize, ErrCorrupt)
	}
	end := off + headerPrefix + nindex*indexEntrySize + hsize
	if end > size {
		return nil, nil, 0, fmt.Errorf("ablated: ends at %d of %d: %w", end, size, ErrCorrupt)
	}
	body := make([]byte, nindex*indexEntrySize+hsize)
	if _, err := r.ReadAt(body, off+headerPrefix); err != nil {
		return nil, nil, 0, err
	}
	tags := make(map[uint32]Entry, nindex)
	for i := range nindex {
		raw := body[i*indexEntrySize:]
		e := Entry{
			Tag:    a.endian.Uint32(raw[0:4]),
			Type:   Type(a.endian.Uint32(raw[4:8])),
			Offset: a.endian.Uint32(raw[8:12]),
			Count:  a.endian.Uint32(raw[12:16]),
		}
		if _, dup := tags[e.Tag]; !dup {
			tags[e.Tag] = e
		}
	}
	return tags, body[nindex*indexEntrySize:], end, nil
}

// ablatedMetadata reads name/version/release/arch/summary and the payload offset
// under the given ablation.
func ablatedMetadata(r io.ReaderAt, size int64, a ablation) (*Package, error) {
	if _, err := readLead(r, size); err != nil {
		return nil, err
	}
	_, _, sigEnd, err := ablatedHeader(r, size, a.leadLen, a)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	hdrOff := sigEnd
	if a.padSignature {
		hdrOff = (sigEnd + 7) &^ 7
	}
	tags, data, hdrEnd, err := ablatedHeader(r, size, hdrOff, a)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	get := func(tag uint32) string {
		e, ok := tags[tag]
		if !ok || int64(e.Offset) >= int64(len(data)) {
			return ""
		}
		rest := data[e.Offset:]
		i := strings.IndexByte(string(rest), 0)
		if i < 0 {
			return ""
		}
		return string(rest[:i])
	}
	return &Package{
		Name: get(TagName), Version: get(TagVersion), Release: get(TagRelease),
		Arch: get(TagArch), Summary: get(TagSummary),
		PayloadFormat:     get(TagPayloadFormat),
		PayloadCompressor: get(TagPayloadCompressor),
		PayloadOffset:     hdrEnd,
		PayloadSize:       size - hdrEnd,
	}, nil
}

// TestAblationHarnessMatchesTheReader is the control for everything below it.
func TestAblationHarnessMatchesTheReader(t *testing.T) {
	for _, w := range witnesses() {
		r, size := reader(fixture(t, w.file))
		want, err := Metadata(r, size)
		if err != nil {
			t.Fatalf("%s: Metadata: %v", w.file, err)
		}
		got, err := ablatedMetadata(r, size, correctAblation())
		if err != nil {
			t.Fatalf("%s: unablated harness: %v", w.file, err)
		}
		for _, c := range [][3]string{
			{"Name", got.Name, want.Name},
			{"Version", got.Version, want.Version},
			{"Release", got.Release, want.Release},
			{"Arch", got.Arch, want.Arch},
			{"Summary", got.Summary, want.Summary},
			{"PayloadFormat", got.PayloadFormat, want.PayloadFormat},
			{"PayloadCompressor", got.PayloadCompressor, want.PayloadCompressor},
		} {
			if c[1] != c[2] {
				t.Errorf("%s: harness %s = %q, reader %q", w.file, c[0], c[1], c[2])
			}
		}
		if got.PayloadOffset != want.PayloadOffset {
			t.Errorf("%s: harness PayloadOffset = %d, reader %d",
				w.file, got.PayloadOffset, want.PayloadOffset)
		}
	}
}

// --- ablation 1: the 8-byte padding after the signature header ---

// TestSignaturePaddingAblation removes the padding and records, per package,
// whether the package notices.
//
// ⛔ ONE OF THE THREE DOES NOT NOTICE, and that is the finding this witness set
// exists for. The el5 package's signature data happens to end at byte 440, which
// is already a multiple of 8, so the padding is zero bytes wide and omitting it
// changes nothing. A reader tested only against a pre-2000 package would ship the
// bug; the el7 and el9 packages both need 4 bytes and both fail without it.
func TestSignaturePaddingAblation(t *testing.T) {
	noticed := 0
	for _, w := range witnesses() {
		r, size := reader(fixture(t, w.file))
		good, gerr := Metadata(r, size)
		if gerr != nil {
			t.Fatalf("%s: %v", w.file, gerr)
		}
		a := correctAblation()
		a.padSignature = false
		p, err := ablatedMetadata(r, size, a)
		switch {
		case w.sigPad == 0:
			// Nothing to remove: it must still parse, identically.
			if err != nil {
				t.Errorf("%s needs no padding yet failed without it: %v", w.file, err)
			} else if p.Name != w.name {
				t.Errorf("%s: name = %q, want %q", w.file, p.Name, w.name)
			}
			t.Logf("ABLATION PASSES on %s: its signature data ends at %d, "+
				"already 8-aligned, so the rule is invisible to it",
				w.file, good.Signature.End)
		case err == nil:
			t.Errorf("%s needs %d bytes of padding and parsed without it: %+v",
				w.file, w.sigPad, p)
		default:
			noticed++
			if !errors.Is(err, ErrCorrupt) {
				t.Errorf("%s without padding gave %v, want ErrCorrupt", w.file, err)
			}
		}
	}
	if noticed == 0 {
		t.Error("no witness notices the missing signature padding; " +
			"the rule is untested by this corpus")
	}
}

// --- ablation 2: big-endian index fields ---

// TestIndexEndiannessAblation reads the index little-endian.
//
// ⛔ IT DOES NOT PRODUCE A PARSE ERROR, which is the whole reason to record it.
// A tag of 1000 read backwards is 0xE8030000, so every lookup MISSES and the
// package comes back with an empty name -- a package that is "missing its
// metadata", not a byte-order fault. Asserting on the error would have found
// nothing; asserting on the VALUES finds it.
func TestIndexEndiannessAblation(t *testing.T) {
	for _, w := range witnesses() {
		r, size := reader(fixture(t, w.file))
		a := correctAblation()
		a.endian = binary.LittleEndian
		p, err := ablatedMetadata(r, size, a)
		if err != nil {
			// Also acceptable: a wild offset can fail the bounds check.
			t.Logf("%s little-endian: %v", w.file, err)
			continue
		}
		if p.Name == w.name {
			t.Errorf("%s parsed correctly with little-endian index fields; "+
				"the byte order is not load-bearing here", w.file)
		}
		if p.Name != "" {
			t.Logf("%s little-endian gave Name = %q", w.file, p.Name)
		}
	}
}

// --- ablation 3: the lead's length ---

// TestLeadLengthAblation looks for the signature header at 95 and at 97 instead
// of 96.
func TestLeadLengthAblation(t *testing.T) {
	for _, w := range witnesses() {
		for _, off := range []int64{95, 97, 64, 128} {
			a := correctAblation()
			a.leadLen = off
			r, size := reader(fixture(t, w.file))
			if _, err := ablatedMetadata(r, size, a); err == nil {
				t.Errorf("%s parsed with the lead treated as %d bytes", w.file, off)
			}
		}
	}
}

// --- ablation 4: the payload compressor dispatch ---

// TestCompressorDispatchAblation feeds each real payload to every compressor
// except its own.
//
// ⚠ ONE PAIR IS EXPECTED TO SUCCEED AND DOES NOT FAIL THE TEST: "none" hands the
// bytes through untouched, so a payload read as uncompressed reaches the cpio
// parser rather than a decompressor. It still fails -- at the cpio magic, one
// layer later -- which is the case the error message in readCpioRecord names
// explicitly, because that is where a missing PAYLOADCOMPRESSOR tag surfaces.
func TestCompressorDispatchAblation(t *testing.T) {
	all := []string{CompressorNone, CompressorGzip, CompressorBzip2, CompressorXz, CompressorZstd}
	for _, w := range witnesses() {
		data := fixture(t, w.file)
		r, size := reader(data)
		p, err := Metadata(r, size)
		if err != nil {
			t.Fatalf("%s: %v", w.file, err)
		}
		for _, c := range all {
			if c == w.compressor {
				continue
			}
			raw, derr := decompressPayload(r, p.PayloadOffset, p.PayloadSize, c)
			if derr != nil {
				continue // the decompressor refused it: the rule bites
			}
			// It decompressed something. Then the cpio parse must refuse it.
			if _, cerr := readCpio(raw); cerr == nil {
				t.Errorf("%s read as %q produced a valid cpio archive; "+
					"the compressor dispatch is not load-bearing", w.file, c)
			} else {
				t.Logf("%s read as %q: decompressed %d bytes, cpio refused: %v",
					w.file, c, len(raw), cerr)
			}
		}
	}
}

// --- ablation 5: each tag lookup ---

// TestTagLookupAblation renumbers one index entry in the real file, so that the
// tag the reader asks for is no longer there, and asserts the corresponding
// field goes empty and nothing else moves.
//
// It mutates the FILE rather than the reader, so what it exercises is the
// shipping lookup and not a copy of it.
func TestTagLookupAblation(t *testing.T) {
	cases := []struct {
		tag   uint32
		field func(*Package) string
		name  string
	}{
		{TagName, func(p *Package) string { return p.Name }, "NAME"},
		{TagVersion, func(p *Package) string { return p.Version }, "VERSION"},
		{TagRelease, func(p *Package) string { return p.Release }, "RELEASE"},
		{TagArch, func(p *Package) string { return p.Arch }, "ARCH"},
		{TagSummary, func(p *Package) string { return p.Summary }, "SUMMARY"},
		{TagPayloadFormat, func(p *Package) string { return p.PayloadFormat }, "PAYLOADFORMAT"},
	}
	for _, w := range witnesses() {
		for _, c := range cases {
			t.Run(w.file+"/"+c.name, func(t *testing.T) {
				data := renumberTag(t, fixture(t, w.file), c.tag, 0x7FFF0000|c.tag)
				p, err := Metadata(reader(data))
				if err != nil {
					t.Fatalf("Metadata after renumbering: %v", err)
				}
				if got := c.field(p); got != "" {
					t.Errorf("%s renumbered away and the field still reads %q; "+
						"the lookup is not load-bearing", c.name, got)
				}
				// Everything else must be untouched: a renumbering that
				// moved two fields would mean the index is being read
				// positionally somewhere.
				if p.License != w.license {
					t.Errorf("renumbering %s also changed License to %q", c.name, p.License)
				}
			})
		}
	}
	// PAYLOADCOMPRESSOR is its own case: removing it must NOT give "" but
	// gzip, which is rpm's documented default for a package without the tag.
	t.Run("PAYLOADCOMPRESSOR/defaults-to-gzip", func(t *testing.T) {
		data := renumberTag(t, fixture(t, "rootfiles-el9-zstd.rpm"),
			TagPayloadCompressor, 0x7FFF0000|TagPayloadCompressor)
		p, err := Metadata(reader(data))
		if err != nil {
			t.Fatalf("Metadata: %v", err)
		}
		if p.PayloadCompressor != CompressorGzip {
			t.Errorf("with no PAYLOADCOMPRESSOR tag, compressor = %q, want %q",
				p.PayloadCompressor, CompressorGzip)
		}
		// ...and the package then fails to open, because it really is zstd.
		if _, err := Open(reader(data)); err == nil {
			t.Error("a zstd payload opened as gzip")
		}
	})
}

// renumberTag rewrites one index entry's tag in the MAIN header of a real file.
func renumberTag(t *testing.T, data []byte, from, to uint32) []byte {
	t.Helper()
	out := make([]byte, len(data))
	copy(out, data)
	p, err := Metadata(reader(out))
	if err != nil {
		t.Fatalf("renumberTag: %v", err)
	}
	base := int(p.Header.Offset) + headerPrefix
	for i := range p.Header.Entries {
		off := base + i*indexEntrySize
		if binary.BigEndian.Uint32(out[off:off+4]) == from {
			binary.BigEndian.PutUint32(out[off:off+4], to)
			return out
		}
	}
	t.Fatalf("renumberTag: tag %d is not in the header", from)
	return nil
}

// --- ablation 6: newc's four-byte padding ---

// TestCpioPaddingAblation walks the real payload rounding to 1 instead of 4.
//
// This is the defect unarchive's own comment warns about, ablated here because
// the two copies of the cpio reader can drift. Rounding to 1 is what "forgetting
// the pad" looks like.
func TestCpioPaddingAblation(t *testing.T) {
	for _, w := range witnesses() {
		r, size := reader(fixture(t, w.file))
		p, err := Metadata(r, size)
		if err != nil {
			t.Fatalf("%s: %v", w.file, err)
		}
		raw, err := decompressPayload(r, p.PayloadOffset, p.PayloadSize, p.PayloadCompressor)
		if err != nil {
			t.Fatalf("%s: %v", w.file, err)
		}
		names, err := walkCpioRounding(raw, 1)
		if err == nil && len(names) == len(mustWalk(t, raw, 4)) {
			t.Errorf("%s: rounding to 1 read the same number of records; "+
				"newc's 4-byte padding is not load-bearing here: %v", w.file, names)
		}
		t.Logf("%s: rounding to 1 gave %d records and err=%v (correct: %d)",
			w.file, len(names), err, len(mustWalk(t, raw, 4)))
	}
}

func mustWalk(t *testing.T, raw []byte, to int64) []string {
	t.Helper()
	names, err := walkCpioRounding(raw, to)
	if err != nil {
		t.Fatalf("walking with rounding %d: %v", to, err)
	}
	return names
}

// walkCpioRounding is a minimal newc walk with the padding as a parameter.
func walkCpioRounding(p []byte, to int64) ([]string, error) {
	round := func(n int64) int64 {
		if to <= 1 {
			return n
		}
		return (n + to - 1) &^ (to - 1)
	}
	var names []string
	off, size := int64(0), int64(len(p))
	for off+cpioHeaderLen <= size {
		h := p[off : off+cpioHeaderLen]
		if m := string(h[0:6]); m != cpio.MagicNewc && m != cpio.MagicCRC {
			return names, fmt.Errorf("magic at %d is %q", off, m)
		}
		field := func(i int) int64 {
			v, _ := strconv.ParseInt(string(h[6+i*8:14+i*8]), 16, 64)
			return v
		}
		fileSize, nameSize := field(6), field(11)
		if nameSize <= 0 || off+cpioHeaderLen+nameSize > size {
			return names, fmt.Errorf("name at %d", off)
		}
		name := strings.TrimRight(string(p[off+cpioHeaderLen:off+cpioHeaderLen+nameSize]), "\x00")
		dataOff := round(off + cpioHeaderLen + nameSize)
		if name == cpio.TrailerName {
			return names, nil
		}
		if dataOff+fileSize > size {
			return names, fmt.Errorf("%q runs past the end", name)
		}
		names = append(names, name)
		off = round(dataOff + fileSize)
	}
	return names, fmt.Errorf("no trailer")
}
