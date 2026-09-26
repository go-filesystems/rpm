// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"compress/bzip2"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/go-filesystems/cpio"
	"io"
	iofs "io/fs"
	"strings"
	"testing"
)

// ⚠ THE TESTS IN THIS FILE USE FIXTURES THIS PACKAGE WROTE. Each one is here
// because no real package in testdata can provide the case: a bzip2 or
// uncompressed payload, a package with no PAYLOADCOMPRESSOR tag, a header
// carrying all ten index types, or a specific corruption. A crafted fixture
// proves a BRANCH RUNS; it does not prove the branch is right about the world.
// The layout itself is witnessed in witness_test.go, against rpmbuild's output.

// --- the compressors, including the two no real package here carries ---

func TestCraftedPayloadPerCompressor(t *testing.T) {
	for _, c := range []string{CompressorGzip, CompressorXz, CompressorZstd, CompressorNone} {
		t.Run(c, func(t *testing.T) {
			data := demoSpec(c).build(t)
			fs, err := Open(reader(data))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			assertDemoPayload(t, fs)
			if fs.Package().PayloadCompressor != c {
				t.Errorf("compressor = %q, want %q", fs.Package().PayloadCompressor, c)
			}
		})
	}
}

// TestBzip2Payload is the only bzip2 witness, and it is doubly crafted: Go has no
// bzip2 writer in its standard library, so the payload was compressed once by
// CPython's bz2 module from a cpio archive that a Python script wrote (recorded in
// testdata/README.md) and committed as a blob.
//
// ⛔ The blob and buildCpio are CROSS-CHECKED here. Two independent writers of the
// same newc layout must produce identical bytes; if they ever stop, this fails
// rather than silently testing a stale blob against a changed builder.
func TestBzip2Payload(t *testing.T) {
	blob := fixture(t, "crafted-payload.cpio.bz2")
	plain, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(blob)))
	if err != nil {
		t.Fatalf("decompressing the committed blob: %v", err)
	}
	if want := buildCpio(demoRecs()...); !bytes.Equal(plain, want) {
		t.Fatalf("the committed bzip2 blob and buildCpio disagree:\n"+
			"blob %d bytes, builder %d bytes", len(plain), len(want))
	}
	s := demoSpec(CompressorBzip2)
	s.rawPayload = blob
	fs, err := Open(reader(s.build(t)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	assertDemoPayload(t, fs)
}

// TestMissingCompressorTagMeansGzip is the crafted-only witness for rpm's
// pre-4.0 default. No package in testdata omits the tag -- even the el5 one
// carries it -- so this proves the BRANCH runs and not that a real 1999 package
// reads correctly. That gap is recorded in doc.go.
func TestMissingCompressorTagMeansGzip(t *testing.T) {
	s := demoSpec("")
	s.rawPayload = compressWith(t, CompressorGzip, s.payload)
	fs, err := Open(reader(s.build(t)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := fs.Package().PayloadCompressor; got != CompressorGzip {
		t.Errorf("compressor with no tag = %q, want %q", got, CompressorGzip)
	}
	assertDemoPayload(t, fs)
}

// assertDemoPayload checks the crafted payload byte for byte, and checks the file
// TYPES the mode switches produce -- which is the reason the demo archive carries
// a fifo, a character device, a block device and a socket that no rootfiles
// package has.
func assertDemoPayload(t *testing.T, fs *FS) {
	t.Helper()
	body, err := fs.ReadFile("etc/demo.conf")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(body) != "key = value\n" {
		t.Errorf("etc/demo.conf = %q", body)
	}
	if b, err := fs.ReadFile("/etc/demo.conf"); err != nil || string(b) != "key = value\n" {
		t.Errorf("a leading slash changed the answer: %q, %v", b, err)
	}
	if b, err := fs.ReadFile("./etc/demo.conf"); err != nil || string(b) != "key = value\n" {
		t.Errorf("a leading ./ changed the answer: %q, %v", b, err)
	}
	target, err := fs.ReadLink("etc/link")
	if err != nil {
		t.Fatalf("ReadLink: %v", err)
	}
	if target != "demo.conf" {
		t.Errorf("etc/link -> %q, want %q", target, "demo.conf")
	}
	// A symlink's size is the target length in the archive; it is reported as
	// 0 here because the target is held as a string, not as payload bytes.
	st, err := fs.Stat("etc/link")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if st.Mode() != 0o120777 {
		t.Errorf("etc/link mode = %o, want 0120777", st.Mode())
	}
	if st.Size() != 0 {
		t.Errorf("etc/link size = %d, want 0", st.Size())
	}
	// Parents nothing declared.
	for _, dir := range []string{"usr", "usr/share", "usr/share/deep"} {
		st, err := fs.Stat(dir)
		if err != nil {
			t.Fatalf("Stat(%q): %v", dir, err)
		}
		if st.Mode() != 0o040755 {
			t.Errorf("%s mode = %o, want 040755", dir, st.Mode())
		}
	}
	if b, err := fs.ReadFile("usr/share/deep/nested.txt"); err != nil || string(b) != "deep\n" {
		t.Errorf("nested.txt = %q, %v", b, err)
	}
	// Every non-regular type, both directions of the mode translation.
	for path, want := range map[string]uint16{
		"dev/fifo":  0o010644,
		"dev/chr":   0o020666,
		"dev/blk":   0o060660,
		"run/sock":  0o140777,
		"etc":       0o040755,
		"etc/link":  0o120777,
		"dev/fifo/": 0o010644,
	} {
		st, err := fs.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%q): %v", path, err)
		}
		if st.Mode() != want {
			t.Errorf("Stat(%q).Mode = %o, want %o", path, st.Mode(), want)
		}
	}
	// ListDir's three DirEntry type codes, in one directory.
	entries, err := fs.ListDir("etc")
	if err != nil {
		t.Fatalf("ListDir(etc): %v", err)
	}
	gotTypes := map[string]uint8{}
	for _, e := range entries {
		gotTypes[e.Name()] = e.FileType()
	}
	if gotTypes["demo.conf"] != fileTypeReg || gotTypes["link"] != fileTypeLink {
		t.Errorf("etc entry types = %v", gotTypes)
	}
	root, err := fs.ListDir(".")
	if err != nil {
		t.Fatalf("ListDir(.): %v", err)
	}
	for _, e := range root {
		if e.FileType() != fileTypeDir {
			t.Errorf("root entry %q type = %d, want %d", e.Name(), e.FileType(), fileTypeDir)
		}
	}
}

// TestDotRecordsAreSkipped covers the branch that drops a record naming the root.
func TestDotRecordsAreSkipped(t *testing.T) {
	s := demoSpec(CompressorNone)
	s.payload = buildCpio(
		cpioRec{name: "./", mode: 0o040755, ino: 1},
		cpioRec{name: ".", mode: 0o040755, ino: 2},
		cpioRec{name: "./a.txt", mode: 0o100644, data: []byte("a"), ino: 3},
	)
	s.rawPayload = s.payload
	fs, err := Open(reader(s.build(t)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entries, err := fs.ListDir("")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "a.txt" {
		t.Errorf("root = %v, want just a.txt", entries)
	}
}

// --- metadata edges ---

func TestEpochAndNEVRA(t *testing.T) {
	s := demoSpec(CompressorNone)
	s.rawPayload = s.payload
	p, err := Metadata(reader(s.build(t)))
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if p.HasEpoch {
		t.Errorf("HasEpoch is true for a package with no EPOCH tag")
	}
	if got, want := p.NEVRA(), "demo-1.0-1.noarch"; got != want {
		t.Errorf("NEVRA = %q, want %q", got, want)
	}
	s2 := demoSpec(CompressorNone)
	s2.rawPayload = s2.payload
	s2.hdr = append(s2.hdr, int32Tag(TagEpoch, 2))
	p2, err := Metadata(reader(s2.build(t)))
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if !p2.HasEpoch || p2.Epoch != 2 {
		t.Errorf("Epoch = %d, HasEpoch = %v", p2.Epoch, p2.HasEpoch)
	}
	if got, want := p2.NEVRA(), "demo-2:1.0-1.noarch"; got != want {
		t.Errorf("NEVRA = %q, want %q", got, want)
	}
	// ⛔ An EPOCH of 0 that IS present is not the same fact as no EPOCH at all,
	// and NEVRA must show the difference.
	s3 := demoSpec(CompressorNone)
	s3.rawPayload = s3.payload
	s3.hdr = append(s3.hdr, int32Tag(TagEpoch, 0))
	p3, err := Metadata(reader(s3.build(t)))
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if !p3.HasEpoch {
		t.Error("an explicit EPOCH of 0 was reported as absent")
	}
	if got, want := p3.NEVRA(), "demo-0:1.0-1.noarch"; got != want {
		t.Errorf("NEVRA = %q, want %q", got, want)
	}
}

func TestAllMetadataStringTagsAreRead(t *testing.T) {
	s := demoSpec(CompressorNone)
	s.rawPayload = s.payload
	s.hdr = append(s.hdr,
		str(TagLicense, "BSD-3-Clause"),
		i18n(TagDescription, "A longer description.\n"),
		str(TagGroup, "Unspecified"),
		str(TagOS, "linux"),
		str(TagVendor, "nobody"),
		str(TagPackager, "nobody <nobody@example.invalid>"),
		str(TagURL, "https://example.invalid/"),
		str(TagSourceRPM, "demo-1.0-1.src.rpm"),
	)
	p, err := Metadata(reader(s.build(t)))
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	for _, c := range [][2]string{
		{p.License, "BSD-3-Clause"},
		{p.Description, "A longer description.\n"},
		{p.Group, "Unspecified"},
		{p.OS, "linux"},
		{p.Vendor, "nobody"},
		{p.Packager, "nobody <nobody@example.invalid>"},
		{p.URL, "https://example.invalid/"},
		{p.SourceRPM, "demo-1.0-1.src.rpm"},
	} {
		if c[0] != c[1] {
			t.Errorf("got %q, want %q", c[0], c[1])
		}
	}
}

func TestUnsupportedPayloadFormatAndCompressor(t *testing.T) {
	s := demoSpec(CompressorNone)
	s.rawPayload = s.payload
	s.format = "drpm"
	if _, err := Open(reader(s.build(t))); !errors.Is(err, ErrUnsupported) {
		t.Errorf("a drpm payload gave %v, want ErrUnsupported", err)
	}
	s2 := demoSpec("lzo")
	s2.rawPayload = s2.payload
	if _, err := Open(reader(s2.build(t))); !errors.Is(err, ErrUnsupported) {
		t.Errorf("an lzo payload gave %v, want ErrUnsupported", err)
	}
	// An ABSENT PAYLOADFORMAT is accepted, exactly as an absent compressor is.
	s3 := demoSpec(CompressorNone)
	s3.rawPayload = s3.payload
	s3.format = ""
	if _, err := Open(reader(s3.build(t))); err != nil {
		t.Errorf("a package with no PAYLOADFORMAT tag: %v", err)
	}
	// OpenReader must return an untyped nil interface on the error path.
	fs, err := OpenReader(reader(s.build(t)))
	if err == nil {
		t.Fatal("OpenReader succeeded on a drpm package")
	}
	if fs != nil {
		t.Errorf("OpenReader returned a non-nil Filesystem alongside an error: %#v", fs)
	}
}

// --- the header, with every index type in one place ---

func TestHeaderAccessorsAcrossEveryType(t *testing.T) {
	const (
		tNull = 100
		tChar = 101
		tI8   = 102
		tI16  = 103
		tI32  = 104
		tI64  = 105
		tStr  = 106
		tBin  = 107
		tArr  = 108
		tI18N = 109
	)
	blob := buildHeader(1, []indexed{
		{tag: tNull, typ: TypeNull, count: 0},
		{tag: tChar, typ: TypeChar, count: 3, data: []byte("abc")},
		{tag: tI8, typ: TypeInt8, count: 2, data: []byte{0x01, 0xFF}},
		{tag: tI16, typ: TypeInt16, count: 2, data: []byte{0x00, 0x2A, 0xFF, 0xFF}},
		{tag: tI32, typ: TypeInt32, count: 2, data: []byte{0, 0, 1, 0, 0xFF, 0xFF, 0xFF, 0xFF}},
		{tag: tI64, typ: TypeInt64, count: 1, data: []byte{0, 0, 0, 0, 0, 0, 0, 7}},
		str(tStr, "one"),
		{tag: tBin, typ: TypeBin, count: 4, data: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		strArray(tArr, "a", "bb", "ccc"),
		i18n(tI18N, "translated"),
	})
	h, err := readHeader(bytes.NewReader(blob), int64(len(blob)), 0, "test")
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if h.Version != 1 {
		t.Errorf("Version = %d, want 1", h.Version)
	}
	if len(h.Entries) != 10 {
		t.Fatalf("Entries = %d, want 10", len(h.Entries))
	}
	// Strings.
	if got := h.String(tStr); got != "one" {
		t.Errorf("String(str) = %q", got)
	}
	if got := h.String(tI18N); got != "translated" {
		t.Errorf("String(i18n) = %q", got)
	}
	if got := h.Strings(tArr); strings.Join(got, ",") != "a,bb,ccc" {
		t.Errorf("Strings(arr) = %v", got)
	}
	if got := h.String(tArr); got != "a" {
		t.Errorf("String(arr) = %q, want the first", got)
	}
	// A string accessor on a non-string type, and on an absent tag.
	if got := h.Strings(tI32); got != nil {
		t.Errorf("Strings(int32) = %v, want nil", got)
	}
	if got := h.String(9999); got != "" {
		t.Errorf("String(absent) = %q", got)
	}
	if got := h.Strings(9999); got != nil {
		t.Errorf("Strings(absent) = %v", got)
	}
	// Integers of every width, negatives included.
	for _, c := range []struct {
		tag  uint32
		want []int64
	}{
		{tChar, []int64{'a', 'b', 'c'}},
		{tI8, []int64{1, -1}},
		{tI16, []int64{42, -1}},
		{tI32, []int64{256, -1}},
		{tI64, []int64{7}},
	} {
		got := h.Ints(c.tag)
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("Ints(%d) = %v, want %v", c.tag, got, c.want)
		}
	}
	if got := h.Ints(tBin); got != nil {
		t.Errorf("Ints(bin) = %v, want nil", got)
	}
	if got := h.Ints(9999); got != nil {
		t.Errorf("Ints(absent) = %v", got)
	}
	if v, ok := h.Int(tI64); !ok || v != 7 {
		t.Errorf("Int(int64) = %d, %v", v, ok)
	}
	if _, ok := h.Int(tNull); ok {
		t.Error("Int on a NULL entry reported a value")
	}
	// Bytes.
	if got := h.Bytes(tBin); !bytes.Equal(got, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("Bytes(bin) = %x", got)
	}
	if got := h.Bytes(tChar); !bytes.Equal(got, []byte("abc")) {
		t.Errorf("Bytes(char) = %q", got)
	}
	if got := h.Bytes(tStr); got != nil {
		t.Errorf("Bytes(string) = %q, want nil", got)
	}
	if got := h.Bytes(9999); got != nil {
		t.Errorf("Bytes(absent) = %v", got)
	}
	// Has and Lookup.
	if !h.Has(tStr) || h.Has(9999) {
		t.Error("Has disagrees with the index")
	}
	if e, ok := h.Lookup(tBin); !ok || e.Type != TypeBin || e.Count != 4 {
		t.Errorf("Lookup(bin) = %+v, %v", e, ok)
	}
	if _, ok := h.Lookup(9999); ok {
		t.Error("Lookup found an absent tag")
	}
}

// TestDuplicateTagKeepsTheFirst covers the de-duplication branch.
func TestDuplicateTagKeepsTheFirst(t *testing.T) {
	blob := buildHeader(1, []indexed{str(TagName, "first"), str(TagName, "second")})
	h, err := readHeader(bytes.NewReader(blob), int64(len(blob)), 0, "test")
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if got := h.String(TagName); got != "first" {
		t.Errorf("String(NAME) = %q, want the first writing", got)
	}
	if len(h.Entries) != 2 {
		t.Errorf("Entries = %d, want both kept in order", len(h.Entries))
	}
}

// --- corruption, one rule at a time ---

func TestCorruptLead(t *testing.T) {
	good := demoSpec(CompressorNone)
	good.rawPayload = good.payload
	data := good.build(t)

	if _, err := Metadata(bytes.NewReader(data[:50]), 50); !errors.Is(err, ErrNotRPM) {
		t.Errorf("a 50-byte file gave %v, want ErrNotRPM", err)
	}
	bad := bytes.Clone(data)
	bad[2] = 0
	if _, err := Metadata(reader(bad)); !errors.Is(err, ErrNotRPM) {
		t.Errorf("a wrong lead magic gave %v, want ErrNotRPM", err)
	}
	// A reader that cannot deliver 96 bytes although the size says it can.
	if _, err := Metadata(&shortReader{data: data[:50]}, int64(len(data))); err == nil {
		t.Error("a truncated reader parsed a lead")
	} else if errors.Is(err, ErrNotRPM) {
		t.Errorf("an I/O failure was reported as ErrNotRPM: %v", err)
	}
}

func TestCorruptHeaders(t *testing.T) {
	good := demoSpec(CompressorNone)
	good.rawPayload = good.payload
	data := good.build(t)
	p, err := Metadata(reader(data))
	if err != nil {
		t.Fatalf("control: %v", err)
	}

	t.Run("signature magic", func(t *testing.T) {
		bad := bytes.Clone(data)
		bad[leadSize] = 0
		mustBeCorrupt(t, bad, "signature")
	})
	t.Run("header magic", func(t *testing.T) {
		bad := bytes.Clone(data)
		bad[p.Header.Offset] = 0
		mustBeCorrupt(t, bad, "header")
	})
	t.Run("nindex beyond the limit", func(t *testing.T) {
		bad := bytes.Clone(data)
		binary.BigEndian.PutUint32(bad[leadSize+8:], maxIndex+1)
		mustBeCorrupt(t, bad, "entries")
	})
	t.Run("hsize beyond the limit", func(t *testing.T) {
		bad := bytes.Clone(data)
		binary.BigEndian.PutUint32(bad[leadSize+12:], maxData+1)
		mustBeCorrupt(t, bad, "data bytes")
	})
	t.Run("header runs past the end of the file", func(t *testing.T) {
		bad := bytes.Clone(data)
		binary.BigEndian.PutUint32(bad[leadSize+12:], 1<<20)
		mustBeCorrupt(t, bad, "past the")
	})
	t.Run("a header body the reader cannot deliver", func(t *testing.T) {
		// The prefix is readable, the body is not.
		trunc := &shortReader{data: data[:leadSize+headerPrefix]}
		if _, err := Metadata(trunc, int64(len(data))); err == nil {
			t.Error("parsed a header whose body could not be read")
		}
	})
	t.Run("readHeader at a negative offset", func(t *testing.T) {
		if _, err := readHeader(bytes.NewReader(data), int64(len(data)), -1, "signature"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("a negative offset gave %v, want ErrCorrupt", err)
		}
	})
	t.Run("no signature padding", func(t *testing.T) {
		s := demoSpec(CompressorNone)
		s.rawPayload = s.payload
		s.padSig = false
		unpadded := s.build(t)
		if len(unpadded) == len(data) {
			t.Fatal("this fixture's signature data is already 8-aligned, " +
				"so omitting the padding changes nothing: the case is not exercised")
		}
		mustBeCorrupt(t, unpadded, "header magic")
	})
}

func mustBeCorrupt(t *testing.T, data []byte, wantIn string) {
	t.Helper()
	_, err := Metadata(reader(data))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), wantIn) {
		t.Errorf("error %q does not mention %q", err, wantIn)
	}
	if errors.Is(err, iofs.ErrNotExist) {
		t.Errorf("a corrupt package reads as fs.ErrNotExist: %v", err)
	}
}

func TestCorruptIndexEntries(t *testing.T) {
	cases := []struct {
		name  string
		entry indexed
		want  string
	}{
		{"offset past the data store", indexed{tag: 1, typ: TypeBin, count: 0, data: nil}, "starts past"},
		{"a fixed value past the end", indexed{tag: 1, typ: TypeInt32, count: 4, data: []byte{0, 0, 0, 0}}, "runs past"},
		{"an int16 past the end", indexed{tag: 1, typ: TypeInt16, count: 4, data: []byte{0, 0}}, "runs past"},
		{"an int64 past the end", indexed{tag: 1, typ: TypeInt64, count: 2, data: []byte{0}}, "runs past"},
		{"a char past the end", indexed{tag: 1, typ: TypeChar, count: 9, data: []byte{0}}, "runs past"},
		{"an unterminated string", indexed{tag: 1, typ: TypeString, count: 1, data: []byte("no NUL")}, "unterminated"},
		{"a type this reader does not know", indexed{tag: 1, typ: Type(42), count: 1, data: []byte{0}}, "does not know"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blob := buildHeader(1, []indexed{c.entry})
			if c.name == "offset past the data store" {
				// buildHeader cannot write an out-of-range offset, so it
				// is patched in: offset 1 with an empty data store.
				binary.BigEndian.PutUint32(blob[headerPrefix+8:], 1)
			}
			_, err := readHeader(bytes.NewReader(blob), int64(len(blob)), 0, "test")
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want ErrCorrupt", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
	// A NULL entry with a non-zero count is accepted: NULL carries nothing, so
	// there is nothing to bound.
	blob := buildHeader(1, []indexed{{tag: 1, typ: TypeNull, count: 5}})
	if _, err := readHeader(bytes.NewReader(blob), int64(len(blob)), 0, "test"); err != nil {
		t.Errorf("a NULL entry was refused: %v", err)
	}
}

// --- the cpio layer ---

func TestCorruptCpio(t *testing.T) {
	good := buildCpio(demoRecs()...)
	// Each numeric field, made non-hexadecimal in turn. The index is newc's own.
	//
	// ⛔ The message is expected to name the FIELD rather than its index, which is
	// what changed when the reader moved to go-filesystems/cpio: "inode at 0" says
	// what is wrong, "field 0" says where to go and count. The index stays here
	// because it is how the corruption is applied.
	//
	// inode and mtime are in this list and were not checked at all on one side of
	// the merge: unarchive ignored their parse errors, so a header with a non-hex
	// inode parsed to inode 0 and looked ordinary. These two cases are why that
	// came out.
	for _, f := range []struct {
		index int
		named string
	}{
		{0, "inode"}, {1, "mode"}, {5, "mtime"}, {6, "size"}, {11, "name size"},
	} {
		t.Run(fmt.Sprintf("field %d (%s) is not hex", f.index, f.named), func(t *testing.T) {
			bad := bytes.Clone(good)
			copy(bad[6+f.index*8:], "zzzzzzzz")
			_, err := readCpio(bad)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want ErrCorrupt", err)
			}
			if !strings.Contains(err.Error(), f.named) {
				t.Errorf("error %q does not name the %s field", err, f.named)
			}
		})
	}
	t.Run("a bad magic in the middle", func(t *testing.T) {
		// The first record is 110 + len("./etc\0")=6 -> padded to 120.
		bad := bytes.Clone(good)
		copy(bad[120:], "XXXXXX")
		if _, err := readCpio(bad); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v, want ErrCorrupt", err)
		}
	})
	t.Run("a zero name size", func(t *testing.T) {
		bad := bytes.Clone(good)
		copy(bad[6+11*8:], "00000000")
		if _, err := readCpio(bad); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v, want ErrCorrupt", err)
		}
	})
	t.Run("a name size past the end", func(t *testing.T) {
		bad := bytes.Clone(good)
		copy(bad[6+11*8:], "0000FFFF")
		if _, err := readCpio(bad); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v, want ErrCorrupt", err)
		}
	})
	t.Run("a file size past the end", func(t *testing.T) {
		bad := bytes.Clone(good)
		copy(bad[6+6*8:], "0000FFFF")
		if _, err := readCpio(bad); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v, want ErrCorrupt", err)
		}
	})
	t.Run("no trailer", func(t *testing.T) {
		// Cut the archive short, at a record boundary, so the walk reaches
		// the end without meeting TRAILER!!!.
		if _, err := readCpio(good[:120]); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v, want ErrCorrupt", err)
		}
		if _, err := readCpio(nil); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("an empty payload gave %v, want ErrCorrupt", err)
		}
	})
	t.Run("the CRC variant is read as newc", func(t *testing.T) {
		crc := bytes.ReplaceAll(good, []byte(cpio.MagicNewc), []byte(cpio.MagicCRC))
		entries, err := readCpio(crc)
		if err != nil {
			t.Fatalf("070702: %v", err)
		}
		if len(entries) != len(demoRecs()) {
			t.Errorf("070702 gave %d entries, want %d", len(entries), len(demoRecs()))
		}
	})
}

// --- the decompressors' own failures ---

func TestDecompressPayloadFailures(t *testing.T) {
	garbage := []byte("this is not a compressed stream at all, not even nearly")
	r := bytes.NewReader(garbage)
	for _, c := range []string{CompressorGzip, CompressorXz, CompressorZstd} {
		if _, err := decompressPayload(r, 0, int64(len(garbage)), c); err == nil {
			t.Errorf("%s accepted garbage", c)
		}
	}
	// bzip2 has no header check at construction: it fails during the copy.
	if _, err := decompressPayload(r, 0, int64(len(garbage)), CompressorBzip2); err == nil {
		t.Error("bzip2 accepted garbage")
	}
	// A valid stream cut in half fails during the copy rather than at open.
	full := compressWith(t, CompressorGzip, buildCpio(demoRecs()...))
	half := full[:len(full)/2]
	if _, err := decompressPayload(bytes.NewReader(half), 0, int64(len(half)), CompressorGzip); err == nil {
		t.Error("a truncated gzip stream was accepted")
	}
	// An unknown compressor, and a negative length.
	if _, err := decompressPayload(r, 0, int64(len(garbage)), "lz4"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("an unknown compressor gave %v, want ErrUnsupported", err)
	}
	if _, err := decompressPayload(r, 0, -1, CompressorNone); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a negative payload length gave %v, want ErrCorrupt", err)
	}
}

// --- the filesystem's refusals ---

func TestWrongKindOfPath(t *testing.T) {
	s := demoSpec(CompressorNone)
	s.rawPayload = s.payload
	fs, err := Open(reader(s.build(t)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := fs.ReadFile("etc"); !errors.Is(err, iofs.ErrInvalid) {
		t.Errorf("ReadFile on a directory gave %v, want fs.ErrInvalid", err)
	}
	if _, err := fs.OpenFile("etc"); !errors.Is(err, iofs.ErrInvalid) {
		t.Errorf("OpenFile on a directory gave %v, want fs.ErrInvalid", err)
	}
	if _, err := fs.ListDir("etc/demo.conf"); !errors.Is(err, iofs.ErrInvalid) {
		t.Errorf("ListDir on a file gave %v, want fs.ErrInvalid", err)
	}
	if _, err := fs.ReadLink("etc/demo.conf"); !errors.Is(err, iofs.ErrInvalid) {
		t.Errorf("ReadLink on a regular file gave %v, want fs.ErrInvalid", err)
	}
	// ⛔ And none of those is fs.ErrNotExist: the path resolved.
	for _, err := range []error{
		mustErr(fs.ReadFile("etc")),
		mustErr(fs.ReadLink("etc/demo.conf")),
	} {
		if errors.Is(err, iofs.ErrNotExist) {
			t.Errorf("a wrong-kind error reads as fs.ErrNotExist: %v", err)
		}
	}
	// OpenFile on a real file: Size, ReadAt and Close.
	f, err := fs.OpenFile("etc/demo.conf")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if f.Size() != 12 {
		t.Errorf("Size = %d, want 12", f.Size())
	}
	buf := make([]byte, 3)
	if n, err := f.ReadAt(buf, 6); n != 3 || err != nil || string(buf) != "val" {
		t.Errorf("ReadAt(6) = %q, %d, %v", buf, n, err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Errorf("fs.Close: %v", err)
	}
}

func mustErr[T any](_ T, err error) error { return err }

// TestHeaderPrefixReadFailure covers the I/O failure that happens while reading
// a header's 16-byte prefix, as distinct from the one while reading its body.
func TestHeaderPrefixReadFailure(t *testing.T) {
	s := demoSpec(CompressorNone)
	s.rawPayload = s.payload
	data := s.build(t)
	// Eight bytes of the signature header's prefix are available; the size
	// says the whole file is there.
	trunc := &shortReader{data: data[:leadSize+8]}
	_, err := Metadata(trunc, int64(len(data)))
	if err == nil {
		t.Fatal("parsed a header whose prefix could not be read")
	}
	if !strings.Contains(err.Error(), "reading the signature header") {
		t.Errorf("error %q does not say which header could not be read", err)
	}
	if errors.Is(err, ErrCorrupt) {
		t.Errorf("an I/O failure was reported as ErrCorrupt: %v", err)
	}
}

// TestOpenRejectsAPayloadThatIsNotCpio covers Open's cpio-failure path: the
// stream decompresses and then is not an archive.
func TestOpenRejectsAPayloadThatIsNotCpio(t *testing.T) {
	s := demoSpec(CompressorNone)
	// Long enough that the walk reads a full 110-byte header rather than
	// stopping at "runs past the payload", so the magic check is what refuses it.
	s.rawPayload = bytes.Repeat([]byte("plainly not a cpio archive. "), 8)
	_, err := Open(reader(s.build(t)))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "cpio magic") {
		t.Errorf("error %q does not name the cpio magic", err)
	}
}

// TestZstdConstructionFailureIsPropagated injects the failure that no input can
// produce. See newZstdReader for what this does and does not establish.
func TestZstdConstructionFailureIsPropagated(t *testing.T) {
	saved := newZstdReader
	t.Cleanup(func() { newZstdReader = saved })
	sentinel := errors.New("injected zstd option failure")
	newZstdReader = func(io.Reader) (io.ReadCloser, error) { return nil, sentinel }
	_, err := decompressPayload(bytes.NewReader([]byte("x")), 0, 1, CompressorZstd)
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want the injected error", err)
	}
	if !strings.Contains(err.Error(), "zstd") {
		t.Errorf("error %q does not name the compressor", err)
	}
}

// cpioHeaderLen is newc's header, and it lives here because only the tests in this
// package WRITE cpio: the reader comes from go-filesystems/cpio, which states the
// padding rule in its own words and has no reason to export an arithmetic constant.
const cpioHeaderLen = 110
