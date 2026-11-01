// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"testing"
)

// FuzzOpen feeds the whole reader -- lead, both headers, the five decompressors,
// the cpio parser, the index -- arbitrary bytes. The ceiling is lowered to 4 MiB so
// that the fuzzer's own memory stays small; the invariants are the ones a hostile
// package could break: no panic, no hang, and every entry an Open accepts can be
// stat'ed and read back inside the payload.
//
// Crashers go to testdata/fuzz AND get a named unit test, because the emulated CI
// lanes run a compiled test binary away from testdata/.
func FuzzOpen(f *testing.F) {
	for _, name := range []string{"rootfiles-el5-gzip.rpm", "rootfiles-el7-xz.rpm", "rootfiles-el9-zstd.rpm"} {
		b, err := fixtures.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	for _, c := range []string{CompressorNone, CompressorGzip, CompressorXz, CompressorZstd} {
		s := demoSpec(c)
		f.Add(s.build(&testing.T{}))
	}
	f.Add(xzStream(xzBlockHeader(false, false, lzma2(31))))
	f.Add(xzValid(xzBlockSpec{40, []byte("planted: a 4 GiB dictionary over a few bytes")}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := Metadata(bytes.NewReader(b), int64(len(b))); err != nil && len(err.Error()) > 4096 {
			t.Fatalf("an error of %d bytes", len(err.Error()))
		}
		fsys, err := OpenLimit(bytes.NewReader(b), int64(len(b)), 4<<20)
		if err != nil {
			return
		}
		root, err := fsys.ListDir("/")
		if err != nil {
			t.Fatalf("ListDir(/): %v", err)
		}
		for _, d := range root {
			st, err := fsys.Stat(d.Name())
			if err != nil {
				t.Fatalf("Stat(%q): %v", d.Name(), err)
			}
			if st.Size() > uint64(len(fsys.payload)) {
				t.Fatalf("%q claims %d bytes of a %d-byte payload", d.Name(), st.Size(), len(fsys.payload))
			}
		}
		for name, e := range fsys.byName {
			if e.mode.IsRegular() && (e.off < 0 || e.size < 0 || e.off+e.size > int64(len(fsys.payload))) {
				t.Fatalf("%q lies outside the payload: off %d size %d of %d", name, e.off, e.size, len(fsys.payload))
			}
		}
	})
}
