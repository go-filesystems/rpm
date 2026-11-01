// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-compressions/xz"
	"github.com/klauspost/compress/zstd"
)

// Bombs: small packages that made the reader allocate, or spin, without bound.
// Every number below was measured on the code before the fix
// (runtime.MemStats TotalAlloc, or wall time, around the call):
//
//	gzip, 526 630 bytes holding one 256 MiB file       1 073 799 504 bytes allocated
//	xz, a 64-byte stream declaring a 512 MiB dictionary  536 929 200 bytes
//	zstd, a 9-byte frame declaring a 512 MiB window      537 151 024 bytes
//	one 1 MiB path "a/a/a/..." (2 329 bytes of package)  Open still running after 9 minutes
//	EPOCH as 64 Mi INT8 values, 67 MB package            603 994 688 bytes
//	NAME as 16 Mi empty strings, 16.7 MB package         285 222 360 bytes
//	8 string arrays of 8 Mi strings over one 8 MiB store 1.55 s (and 65 535 arrays of a 100 MB
//	                                                      store is days)

func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

func openBytes(b []byte, max int64) (*FS, error) {
	return OpenLimit(bytes.NewReader(b), int64(len(b)), max)
}

func TestThePayloadCeilingIsExact(t *testing.T) {
	for _, c := range []string{CompressorNone, CompressorGzip, CompressorXz, CompressorZstd} {
		t.Run(c, func(t *testing.T) {
			s := demoSpec(c)
			pkg := s.build(t)
			n := int64(len(s.payload))
			if _, err := openBytes(pkg, n); err != nil {
				t.Fatalf("a payload of exactly the ceiling (%d): %v", n, err)
			}
			_, err := openBytes(pkg, n-1)
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("one byte over: %v, want ErrTooLarge", err)
			}
			if errors.Is(err, ErrCorrupt) {
				t.Errorf("a size refusal was reported as corruption: %v", err)
			}
		})
	}
	// Zero means the default, and a ceiling no int can hold is clamped, not trusted.
	pkg := demoSpec(CompressorGzip).build(t)
	for _, max := range []int64{0, -1, math.MaxInt64} {
		if _, err := openBytes(pkg, max); err != nil {
			t.Errorf("OpenLimit(%d): %v", max, err)
		}
	}
	if _, err := Open(bytes.NewReader(pkg), int64(len(pkg))); err != nil {
		t.Errorf("Open: %v", err)
	}
}

func TestAGzipBombIsRefusedWithoutHoldingIt(t *testing.T) {
	payload := buildCpio(cpioRec{name: "./z", mode: 0o100644, data: make([]byte, 32<<20), ino: 1})
	s := demoSpec(CompressorGzip)
	s.payload = payload
	pkg := s.build(t)
	if len(pkg) > 100<<10 {
		t.Fatalf("the fixture is %d bytes: not a bomb", len(pkg))
	}
	var err error
	got := allocated(func() { _, err = openBytes(pkg, 1<<20) })
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Open = %v, want ErrTooLarge", err)
	}
	// 1 MiB held, doubled by the buffer (measured 8.4 MB under -race), against the
	// 128 MB the same payload cost before the ceiling.
	if got > 16<<20 {
		t.Errorf("%d bytes allocated to refuse a %d-byte package", got, len(pkg))
	}
}

// xzBlockHeader builds a Block Header (xz-file-format.txt, 3.1) for the filters.
func xzBlockHeader(csize, usize bool, filters ...[]byte) []byte {
	flags := byte(len(filters) - 1)
	var body []byte
	if csize {
		flags |= 0x40
		body = binary.AppendUvarint(body, 1000)
	}
	if usize {
		flags |= 0x80
		body = binary.AppendUvarint(body, 1<<20)
	}
	for _, f := range filters {
		body = append(body, f...)
	}
	body = append([]byte{flags}, body...)
	size := (1 + len(body) + 4 + 3) &^ 3
	hdr := make([]byte, size)
	hdr[0] = byte(size/4 - 1)
	copy(hdr[1:], body)
	binary.LittleEndian.PutUint32(hdr[size-4:], crc32.ChecksumIEEE(hdr[:size-4]))
	return hdr
}

func xzStream(block []byte) []byte {
	flags := []byte{0x00, 0x01} // CRC32 check
	out := append([]byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, flags...)
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(flags))
	return append(out, block...)
}

func lzma2(bits byte) []byte { return []byte{0x21, 0x01, bits} }

// xzBlockSpec is one block of a stream built by xzValid: the LZMA2 dictionary
// property its header declares, and the bytes it stores.
type xzBlockSpec struct {
	prop byte
	data []byte
}

// xzStored wraps data in LZMA2 uncompressed chunks and the 0x00 end marker
// (xz-file-format.txt, 5.3.1; no encoder needed).
func xzStored(data []byte) []byte {
	var out []byte
	first := true
	for len(data) > 0 {
		n := min(len(data), 1<<16)
		ctl := byte(2) // uncompressed chunk, no dictionary reset
		if first {
			ctl, first = 1, false // uncompressed chunk, dictionary reset
		}
		out = append(out, ctl, byte((n-1)>>8), byte(n-1))
		out = append(out, data[:n]...)
		data = data[n:]
	}
	return append(out, 0)
}

// xzValid builds a complete, valid .xz stream (CRC32 check) of the blocks: header
// and footer, Block Headers without sizes, Index. Valid streams that declare a
// dictionary of any size over a few bytes are the bombs.
func xzValid(blocks ...xzBlockSpec) []byte {
	out := xzStream(nil)
	index := []byte{0x00}
	index = binary.AppendUvarint(index, uint64(len(blocks)))
	for _, b := range blocks {
		hdr := xzBlockHeader(false, false, lzma2(b.prop))
		blk := append(hdr, xzStored(b.data)...)
		unpadded := uint64(len(blk)) + 4
		for len(blk)%4 != 0 {
			blk = append(blk, 0)
		}
		blk = binary.LittleEndian.AppendUint32(blk, crc32.ChecksumIEEE(b.data))
		out = append(out, blk...)
		index = binary.AppendUvarint(index, unpadded)
		index = binary.AppendUvarint(index, uint64(len(b.data)))
	}
	for len(index)%4 != 0 {
		index = append(index, 0)
	}
	index = binary.LittleEndian.AppendUint32(index, crc32.ChecksumIEEE(index))
	out = append(out, index...)
	footer := binary.LittleEndian.AppendUint32(nil, uint32(len(index)/4-1))
	footer = append(footer, 0x00, 0x01)
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(footer))
	return append(append(out, footer...), 'Y', 'Z')
}

// TestAnXZDictionaryBombAllocatesNothing: a valid package whose payload declares an
// LZMA2 dictionary of 1 GiB, 1.5 GiB or 4 GiB - 1 over a few bytes. Measured before
// (ulikunitz/xz v0.5.17, a 44-byte stream declaring 1.5 GiB): 1 610 663 976 bytes
// allocated. go-compressions/xz sizes the window by the data decoded.
func TestAnXZDictionaryBombAllocatesNothing(t *testing.T) {
	cpio := demoSpec(CompressorXz).payload
	for _, prop := range []byte{36, 37, 40} {
		s := demoSpec(CompressorXz)
		s.rawPayload = xzValid(xzBlockSpec{prop, cpio})
		pkg := s.build(t)
		var err error
		got := allocated(func() { _, err = openBytes(pkg, DefaultMaxPayload) })
		if err != nil {
			t.Fatalf("prop %d: Open = %v, want it to decode", prop, err)
		}
		t.Logf("prop %d: %d bytes allocated by Open", prop, got)
		if got > 1<<20 {
			t.Errorf("prop %d: %d bytes allocated", prop, got)
		}
	}
	// A bare header with no data is refused as corrupt, still without allocating.
	s := demoSpec(CompressorXz)
	s.rawPayload = xzStream(xzBlockHeader(false, false, lzma2(40)))
	pkg := s.build(t)
	var err error
	got := allocated(func() { _, err = openBytes(pkg, DefaultMaxPayload) })
	if !errors.Is(err, xz.ErrTruncated) || errors.Is(err, ErrTooLarge) {
		t.Errorf("a header alone: %v, want the library's ErrTruncated", err)
	}
	if got > 1<<20 {
		t.Errorf("a header alone: %d bytes allocated", got)
	}
}

// TestTheXZDictionaryCeilingIsExact: the window grows with the data and stops at
// the ceiling, whatever the header declares. The ceiling is lowered for the test
// (xzMaxDictionary) so that no test needs 128 MiB of output.
func TestTheXZDictionaryCeilingIsExact(t *testing.T) {
	defer func(old int) { xzMaxDictionary = old }(xzMaxDictionary)
	data := bytes.Repeat([]byte("0123456789abcdef"), 1<<14) // 256 KiB
	for _, prop := range []byte{40, 18} {                  // 4 GiB - 1, and 2 MiB
		stream := xzValid(xzBlockSpec{prop, data})
		decode := func(ceiling int) ([]byte, error) {
			xzMaxDictionary = ceiling
			return decompressPayload(bytes.NewReader(stream), 0, int64(len(stream)), CompressorXz, DefaultMaxPayload)
		}
		got, err := decode(len(data))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("prop %d, a ceiling of exactly the data: %v", prop, err)
		}
		_, err = decode(len(data) - 1)
		if !errors.Is(err, ErrTooLarge) || errors.Is(err, ErrCorrupt) {
			t.Fatalf("prop %d, one byte under: %v, want ErrTooLarge", prop, err)
		}
		if !errors.Is(err, xz.ErrTooLarge) {
			t.Errorf("prop %d: %v does not wrap the library's error", prop, err)
		}
	}
}

// TestAnXZBombInALaterBlockOrStreamIsRefused: the guard this replaced read the first
// Block Header of the first stream only. The ceiling is in the decoder now, so a
// benign first block, or a benign first stream, protects nothing.
func TestAnXZBombInALaterBlockOrStreamIsRefused(t *testing.T) {
	defer func(old int) { xzMaxDictionary = old }(xzMaxDictionary)
	xzMaxDictionary = 1 << 20
	benign := xzBlockSpec{18, []byte("small")}
	big := xzBlockSpec{40, bytes.Repeat([]byte{7}, 3<<20)}
	for name, stream := range map[string][]byte{
		"second block":  xzValid(benign, big),
		"second stream": append(xzValid(benign), xzValid(big)...),
	} {
		_, err := decompressPayload(bytes.NewReader(stream), 0, int64(len(stream)), CompressorXz, DefaultMaxPayload)
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v, want ErrTooLarge", name, err)
		}
	}
}

func TestAZstdWindowBombIsRefusedBeforeItIsAllocated(t *testing.T) {
	// magic, a frame header descriptor of 0 (no single segment, no content size),
	// the window byte, then one empty raw last block.
	frame := func(window byte) []byte {
		return []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, window, 0x01, 0x00, 0x00}
	}
	for _, w := range []byte{0x90, 0x98, 0xA0} { // 256 MiB, 512 MiB, 1 GiB
		s := demoSpec(CompressorZstd)
		s.rawPayload = frame(w)
		pkg := s.build(t)
		var err error
		got := allocated(func() { _, err = openBytes(pkg, DefaultMaxPayload) })
		if !errors.Is(err, ErrTooLarge) || !errors.Is(err, zstd.ErrWindowSizeExceeded) {
			t.Errorf("window byte %#x: %v, want ErrTooLarge wrapping the library's error", w, err)
		}
		if got > 1<<20 {
			t.Errorf("window byte %#x: %d bytes allocated", w, got)
		}
	}
	// A small window is decoded: the empty payload then fails as a cpio, not as a size.
	s := demoSpec(CompressorZstd)
	s.rawPayload = frame(0x40)
	if _, err := openBytes(s.build(t), DefaultMaxPayload); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a 256 KiB window: %v, want it to reach the cpio and fail there", err)
	}
}

// assemble puts a main header behind a lead and a signature header, with no payload.
func assemble(hdr []byte) []byte {
	var out bytes.Buffer
	out.Write(buildLead("p-1-1"))
	out.Write(buildHeader(1, []indexed{int32Tag(SigTagSize, 1)}))
	for out.Len()%8 != 0 {
		out.WriteByte(0)
	}
	out.Write(hdr)
	return out.Bytes()
}

// rawHeader builds a header whose entries all point at explicit offsets, which
// buildHeader cannot: it lays every value out one after another.
func rawHeader(entries []Entry, data []byte) []byte {
	var out bytes.Buffer
	out.Write(headerMagic[:])
	out.Write([]byte{1, 0, 0, 0, 0})
	out.Write(binary.BigEndian.AppendUint32(nil, uint32(len(entries))))
	out.Write(binary.BigEndian.AppendUint32(nil, uint32(len(data))))
	for _, e := range entries {
		for _, v := range []uint32{e.Tag, uint32(e.Type), e.Offset, e.Count} {
			out.Write(binary.BigEndian.AppendUint32(nil, v))
		}
	}
	out.Write(data)
	return out.Bytes()
}

// TestTheScanBudgetIsExact: k entries that each walk the whole store use k times
// its length. The budget is twice the length, so two entries pass and a third is
// refused -- and it is refused after a bounded amount of work, not after k walks.
func TestTheScanBudgetIsExact(t *testing.T) {
	const store = 4096
	for k, wantErr := range map[int]bool{1: false, 2: false, 3: true, 5000: true} {
		var es []Entry
		for i := range k {
			es = append(es, Entry{Tag: uint32(5000 + i), Type: TypeStringArray, Count: store})
		}
		pkg := assemble(rawHeader(es, make([]byte, store)))
		_, err := Metadata(bytes.NewReader(pkg), int64(len(pkg)))
		if wantErr != (err != nil) {
			t.Errorf("%d entries over a %d-byte store: err=%v, want error=%v", k, store, err, wantErr)
		}
		if wantErr && !errors.Is(err, ErrCorrupt) {
			t.Errorf("%d entries: %v is not ErrCorrupt", k, err)
		}
	}
}

func TestStringAndIntBuildNothingButTheirAnswer(t *testing.T) {
	const n = 1 << 20
	hdr := buildHeader(1, []indexed{
		{tag: TagName, typ: TypeStringArray, count: n, data: make([]byte, n)},
		{tag: TagEpoch, typ: TypeInt8, count: n, data: make([]byte, n)},
	})
	pkg := assemble(hdr)
	m, err := Metadata(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatal(err)
	}
	var s string
	if got := allocated(func() { s = m.Header.String(TagName) }); got > 1<<10 || s != "" {
		t.Errorf("String of a %d-string array allocated %d bytes (answer %q)", n, got, s)
	}
	var v int64
	var ok bool
	if got := allocated(func() { v, ok = m.Header.Int(TagEpoch) }); got > 1<<10 || !ok || v != 0 {
		t.Errorf("Int of a %d-value array allocated %d bytes (answer %d, %v)", n, got, v, ok)
	}
	// Measured before: 16 MiB and 8 MiB for the same two calls.
}

func TestStringAndIntAnswerOnlyForTheirTypes(t *testing.T) {
	hdr := buildHeader(1, []indexed{
		{tag: 7000, typ: TypeStringArray, count: 0, data: []byte{0}},
		{tag: 7001, typ: TypeInt32, count: 1, data: []byte{0, 0, 0, 5}},
		{tag: 7002, typ: TypeBin, count: 2, data: []byte{1, 2}},
		{tag: 7003, typ: TypeInt32, count: 0, data: []byte{0, 0, 0, 5}},
		str(7004, "first"),
		strArray(7005, "a", "b"),
	})
	pkg := assemble(hdr)
	m, err := Metadata(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatal(err)
	}
	h := m.Header
	for tag, want := range map[uint32]string{7000: "", 7001: "", 7002: "", 7004: "first", 7005: "a", 9999: ""} {
		if got := h.String(tag); got != want {
			t.Errorf("String(%d) = %q, want %q", tag, got, want)
		}
	}
	if v, ok := h.Int(7001); !ok || v != 5 {
		t.Errorf("Int(7001) = %d, %v", v, ok)
	}
	for _, tag := range []uint32{7000, 7002, 7003, 7004, 9999} {
		if v, ok := h.Int(tag); ok {
			t.Errorf("Int(%d) = %d, true; want no integer", tag, v)
		}
	}
}

func TestAHeaderOverRpmsOwnLimitsIsRefused(t *testing.T) {
	if maxIndex != 0xffff || maxData != 0x0fffffff {
		t.Fatalf("maxIndex %#x, maxData %#x: not rpm's HEADER_TAGS_MAX and HEADER_DATA_MAX", maxIndex, maxData)
	}
}

// pkgWithRecords builds a package whose payload is the given cpio records.
func pkgWithRecords(t *testing.T, recs ...cpioRec) []byte {
	s := demoSpec(CompressorGzip)
	s.payload = buildCpio(recs...)
	return s.build(t)
}

func TestAPathLongerThanPathMaxIsRefused(t *testing.T) {
	ok := pkgWithRecords(t, cpioRec{name: strings.Repeat("a", MaxPathLength), mode: 0o100644, ino: 1})
	if _, err := openBytes(ok, DefaultMaxPayload); err != nil {
		t.Fatalf("a path of exactly MaxPathLength: %v", err)
	}
	over := pkgWithRecords(t, cpioRec{name: strings.Repeat("a", MaxPathLength+1), mode: 0o100644, ino: 1})
	if _, err := openBytes(over, DefaultMaxPayload); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one over: %v, want ErrTooLarge", err)
	}
	// And the bomb itself: a megabyte of "a/a/a/...", about 2 KB of package.
	bomb := pkgWithRecords(t, cpioRec{name: "./" + strings.Repeat("a/", 1<<19-8) + "f", mode: 0o100644, ino: 1})
	var err error
	d := time.Now()
	if _, err = openBytes(bomb, DefaultMaxPayload); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("the deep-path bomb: %v, want ErrTooLarge", err)
	}
	if took := time.Since(d); took > 5*time.Second {
		t.Errorf("refusing it took %v", took)
	}
}

func TestADeepPathAtTheCeilingIsIndexedOnce(t *testing.T) {
	name := "./" + strings.Repeat("a/", MaxPathLength/2-2) + "f" // 4095 bytes
	pkg := pkgWithRecords(t, cpioRec{name: name, mode: 0o100644, data: []byte("x"), ino: 1})
	fsys, err := openBytes(pkg, DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	// Every ancestor was synthesised and is listed under its own parent.
	dir := strings.TrimSuffix(strings.TrimPrefix(name, "./"), "/f")
	kids, err := fsys.ListDir(dir)
	if err != nil || len(kids) != 1 {
		t.Fatalf("ListDir(deepest): %v, %v", kids, err)
	}
	if got, err := fsys.ReadFile(name); err != nil || string(got) != "x" {
		t.Errorf("ReadFile: %q, %v", got, err)
	}
}

func TestTheEntryCeilingCountsParentDirectories(t *testing.T) {
	defer func(old int) { maxEntries = old }(maxEntries)
	maxEntries = 10
	files := func(n int, dirs bool) []cpioRec {
		var rs []cpioRec
		for i := range n {
			name := fmt.Sprintf("./f%d", i)
			if dirs {
				name = fmt.Sprintf("./d%d/f", i) // each in a directory nothing declared
			}
			rs = append(rs, cpioRec{name: name, mode: 0o100644, ino: int64(i + 1)})
		}
		return rs
	}
	for _, tc := range []struct {
		name string
		recs []cpioRec
		ok   bool
	}{
		{"10 real entries", files(10, false), true},
		{"11 real entries", files(11, false), false},
		{"5 files and their 5 synthesised directories", files(5, true), true},
		{"6 files and their 6 synthesised directories", files(6, true), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := openBytes(pkgWithRecords(t, tc.recs...), DefaultMaxPayload)
			if tc.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("Open = %v, want ErrTooLarge", err)
			}
		})
	}
}

// TestAWideDirectoryIsLinear: indexing N files in one directory used to cost N²/2
// string comparisons. 200 000 of them take about 20 ms now and would take about
// 20 s with the scan (2 x 10^10 comparisons), so a bound of 5 s tells the two apart
// by a factor of 250 either way and does not depend on the machine being quick.
// (A ratio of the times for N and 4N was tried first and was too noisy: 4 to 7 for
// linear code under load, against 16 for quadratic.)
func TestAWideDirectoryIsLinear(t *testing.T) {
	const n = 200000
	entries := make([]entry, n)
	for i := range entries {
		entries[i] = entry{name: fmt.Sprintf("d/f%d", i), mode: 0o100644}
	}
	d := time.Now()
	if _, err := newFS(&Package{}, nil, entries); err != nil {
		t.Fatal(err)
	}
	took := time.Since(d)
	t.Logf("%d entries in one directory: %v", n, took)
	if took > 5*time.Second {
		t.Errorf("%d entries took %v: the index is not linear", n, took)
	}
}

// TestACpioWithANegativeSizeIsRefused: cpio v0.6.0 re-read record one for ever on
// it, appending a record each time, and the payload of a package is exactly the
// input that reached it.
func TestACpioWithANegativeSizeIsRefused(t *testing.T) {
	name := append([]byte("a"), 0)
	hdr := fmt.Sprintf("070701%08X%08X%08X%08X%08X%08X%s%08X%08X%08X%08X%08X%08X",
		1, 0o100644, 0, 0, 1, 0, "-0000070", 0, 0, 0, 0, len(name), 0)
	s := demoSpec(CompressorNone)
	s.rawPayload = append(append([]byte(hdr), name...), 0) // 110 + 2 = 112 = the data offset
	pkg := s.build(t)
	done := make(chan error, 1)
	go func() { _, err := openBytes(pkg, DefaultMaxPayload); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open = %v, want ErrCorrupt", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Open did not return: the cpio walk is going round in circles")
	}
}
