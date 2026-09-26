// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// ⚠⚠ EVERYTHING IN THIS FILE IS A FIXTURE OF THE READER'S OWN MAKING, AND THAT
// IS A WEAKER WITNESS THAN A REAL PACKAGE.
//
// A fixture written from the same understanding of the format as the parser
// cannot fail the way a real package can: if that understanding is wrong in the
// same way on both sides, the test agrees with the bug. The 8-byte padding is the
// clearest case -- a builder that omits it and a parser that omits it round-trip
// perfectly, and every real RPM built since 2000 fails.
//
// So the builder is here for what real packages CANNOT provide -- a bzip2
// payload, an uncompressed payload, a missing PAYLOADCOMPRESSOR tag, every index
// type in one header, and each corruption in turn -- and rpm_test.go's real
// witnesses carry the load for the layout itself. Where a crafted fixture is the
// only witness for a rule, the test that uses it says so.

// indexed is one value to store in a header, before its offset is known.
type indexed struct {
	tag   uint32
	typ   Type
	count uint32
	data  []byte
}

func str(tag uint32, s string) indexed {
	return indexed{tag: tag, typ: TypeString, count: 1, data: append([]byte(s), 0)}
}

func strArray(tag uint32, ss ...string) indexed {
	var b []byte
	for _, s := range ss {
		b = append(b, append([]byte(s), 0)...)
	}
	return indexed{tag: tag, typ: TypeStringArray, count: uint32(len(ss)), data: b}
}

func i18n(tag uint32, s string) indexed {
	return indexed{tag: tag, typ: TypeI18NString, count: 1, data: append([]byte(s), 0)}
}

func int32Tag(tag uint32, vs ...int32) indexed {
	b := make([]byte, 0, 4*len(vs))
	for _, v := range vs {
		b = binary.BigEndian.AppendUint32(b, uint32(v))
	}
	return indexed{tag: tag, typ: TypeInt32, count: uint32(len(vs)), data: b}
}

// buildHeader assembles one header structure: magic, version, reserved, nindex,
// hsize, the index, then the data store.
func buildHeader(version byte, entries []indexed) []byte {
	var index, data bytes.Buffer
	for _, e := range entries {
		index.Write(binary.BigEndian.AppendUint32(nil, e.tag))
		index.Write(binary.BigEndian.AppendUint32(nil, uint32(e.typ)))
		index.Write(binary.BigEndian.AppendUint32(nil, uint32(data.Len())))
		index.Write(binary.BigEndian.AppendUint32(nil, e.count))
		data.Write(e.data)
	}
	var out bytes.Buffer
	out.Write(headerMagic[:])
	out.WriteByte(version)
	out.Write([]byte{0, 0, 0, 0})
	out.Write(binary.BigEndian.AppendUint32(nil, uint32(len(entries))))
	out.Write(binary.BigEndian.AppendUint32(nil, uint32(data.Len())))
	out.Write(index.Bytes())
	out.Write(data.Bytes())
	return out.Bytes()
}

// buildLead writes a valid 96-byte lead for the given NVR.
func buildLead(nvr string) []byte {
	b := make([]byte, leadSize)
	copy(b, leadMagic[:])
	b[4], b[5] = 3, 0
	binary.BigEndian.PutUint16(b[6:8], 0)  // binary package
	binary.BigEndian.PutUint16(b[8:10], 1) // archnum: whatever; never read
	copy(b[10:76], nvr)
	binary.BigEndian.PutUint16(b[76:78], 1) // Linux
	binary.BigEndian.PutUint16(b[78:80], 5)
	return b
}

// spec describes a package to build.
type spec struct {
	nvr        string
	sig        []indexed
	hdr        []indexed
	padSig     bool // false omits the 8-byte alignment, which is the ablation
	payload    []byte
	compressor string // "" leaves PAYLOADCOMPRESSOR out entirely
	format     string // "" leaves PAYLOADFORMAT out entirely
	rawPayload []byte // when set, used verbatim instead of compressing payload
}

// build assembles a whole .rpm.
func (s spec) build(t *testing.T) []byte {
	t.Helper()
	hdr := s.hdr
	if s.format != "" {
		hdr = append(hdr, str(TagPayloadFormat, s.format))
	}
	if s.compressor != "" {
		hdr = append(hdr, str(TagPayloadCompressor, s.compressor))
	}
	var out bytes.Buffer
	out.Write(buildLead(s.nvr))
	sigBlob := buildHeader(1, s.sig)
	out.Write(sigBlob)
	if s.padSig {
		for out.Len()%8 != 0 {
			out.WriteByte(0)
		}
	}
	out.Write(buildHeader(1, hdr))
	switch {
	case s.rawPayload != nil:
		out.Write(s.rawPayload)
	default:
		out.Write(compressWith(t, s.compressor, s.payload))
	}
	return out.Bytes()
}

// compressWith wraps the payload in the named compressor. bzip2 is absent: Go
// has no bzip2 writer in the standard library, so the one bzip2 witness is a
// pre-compressed blob in testdata -- see TestBzip2Payload.
func compressWith(t *testing.T, name string, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch name {
	case "", CompressorGzip:
		w := gzip.NewWriter(&buf)
		mustWrite(t, w, raw)
		if err := w.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	case CompressorNone:
		return raw
	case CompressorXz:
		w, err := xz.NewWriter(&buf)
		if err != nil {
			t.Fatalf("xz writer: %v", err)
		}
		mustWrite(t, w, raw)
		if err := w.Close(); err != nil {
			t.Fatalf("xz close: %v", err)
		}
	case CompressorZstd:
		w, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatalf("zstd writer: %v", err)
		}
		mustWrite(t, w, raw)
		if err := w.Close(); err != nil {
			t.Fatalf("zstd close: %v", err)
		}
	default:
		t.Fatalf("compressWith: no writer for %q", name)
	}
	return buf.Bytes()
}

func mustWrite(t *testing.T, w interface{ Write([]byte) (int, error) }, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// --- cpio ---

// cpioRec is one record to write.
type cpioRec struct {
	name string
	mode int64
	data []byte
	ino  int64
}

// buildCpio writes a newc archive, trailer included.
//
// ⚠ It is a SECOND implementation of newc's layout, independent of the reader's
// -- and the two are cross-checked against each other by TestBzip2Payload, whose
// committed blob was produced by a THIRD (a Python script, recorded in
// testdata/README.md). Two implementations that agree are weak evidence and
// three are not much stronger; the real packages in rpm_test.go are the evidence.
func buildCpio(recs ...cpioRec) []byte {
	var out bytes.Buffer
	write := func(r cpioRec) {
		name := append([]byte(r.name), 0)
		h := fmt.Sprintf("070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			r.ino, r.mode, 0, 0, 1, 0x5F000000, len(r.data), 0, 0, 0, 0, len(name), 0)
		out.WriteString(h)
		out.Write(name)
		for out.Len()%4 != 0 {
			out.WriteByte(0)
		}
		out.Write(r.data)
		for out.Len()%4 != 0 {
			out.WriteByte(0)
		}
	}
	for _, r := range recs {
		write(r)
	}
	write(cpioRec{name: cpioTrailer, ino: 0})
	return out.Bytes()
}

// demoRecs is the payload every crafted fixture carries, chosen so that one
// archive exercises each file type the mode switches know about, a nested path
// whose parents are NOT declared (so directory synthesis runs), and a regular
// file with bytes to assert.
func demoRecs() []cpioRec {
	return []cpioRec{
		{name: "./etc", mode: 0o040755, ino: 1},
		{name: "./etc/demo.conf", mode: 0o100644, data: []byte("key = value\n"), ino: 2},
		{name: "./etc/link", mode: 0o120777, data: []byte("demo.conf"), ino: 3},
		{name: "./usr/share/deep/nested.txt", mode: 0o100600, data: []byte("deep\n"), ino: 4},
		{name: "./dev/fifo", mode: 0o010644, ino: 5},
		{name: "./dev/chr", mode: 0o020666, ino: 6},
		{name: "./dev/blk", mode: 0o060660, ino: 7},
		{name: "./run/sock", mode: 0o140777, ino: 8},
	}
}

// demoSpec is a complete, well-formed crafted package.
func demoSpec(compressor string) spec {
	return spec{
		nvr: "demo-1.0-1",
		sig: []indexed{int32Tag(SigTagSize, 1234)},
		hdr: []indexed{
			str(TagName, "demo"),
			str(TagVersion, "1.0"),
			str(TagRelease, "1"),
			str(TagArch, "noarch"),
			i18n(TagSummary, "A crafted package"),
		},
		padSig:     true,
		payload:    buildCpio(demoRecs()...),
		compressor: compressor,
		format:     PayloadFormatCpio,
	}
}
