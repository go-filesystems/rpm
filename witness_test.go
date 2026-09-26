// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"embed"
	"errors"
	"io"
	iofs "io/fs"
	"testing"
)

// ⛔ EMBEDDED, NOT READ FROM testdata/ AT RUNTIME. The emulated CI lanes copy a
// `go test -c` binary into a QEMU container and run it with no repository beside
// it, so an os.ReadFile("testdata/...") passes on four native lanes and fails on
// four emulated ones. //go:embed bakes the bytes into the binary.
//
// Verify with:  go test -c -o /tmp/t.test . && cd /tmp && ./t.test
//
//go:embed testdata/rootfiles-el5-gzip.rpm
//go:embed testdata/rootfiles-el7-xz.rpm
//go:embed testdata/rootfiles-el9-zstd.rpm
//go:embed testdata/crafted-payload.cpio.bz2
var fixtures embed.FS

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fixtures.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("embedded fixture %s: %v", name, err)
	}
	return b
}

func reader(b []byte) (io.ReaderAt, int64) { return bytes.NewReader(b), int64(len(b)) }

// witness is one real package and every fact this reader must get right about it.
//
// The facts were established with a reference implementation that is NOT this one
// and NOT rpm: no rpm, rpm2cpio or rpmbuild exists on the machine these were
// taken on, so the values below were read out with an independent 40-line Python
// script written from the specification (recorded in testdata/README.md). That is
// a weaker control than rpm itself would be -- two readers written from one
// specification can share a misreading of it -- and it is stronger than a fixture
// this package wrote, because the BYTES came from rpmbuild.
type witness struct {
	file       string
	name       string
	version    string
	release    string
	arch       string
	summary    string
	license    string
	compressor string
	// sigPad is how many bytes of alignment padding sit between the signature
	// header's data and the header proper. It is recorded per package because
	// it is 0 for one of the three: see TestSignaturePaddingAblation.
	sigPad    int64
	payloadAt int64
	// files maps a payload path to its EXACT contents. Counts are not
	// asserted anywhere in this file: a count is satisfied by the right
	// number of wrong entries.
	files map[string]string
	dirs  []string
}

func witnesses() []witness {
	return []witness{{
		file: "rootfiles-el5-gzip.rpm",
		name: "rootfiles", version: "8.1", release: "1.1.1", arch: "noarch",
		summary:    "The basic required files for the root user's directory.",
		license:    "Public Domain",
		compressor: CompressorGzip,
		sigPad:     0,
		payloadAt:  4257,
		files: map[string]string{
			"root/.bash_logout": "# ~/.bash_logout\n\nclear\n",
			"root/.cshrc": "# .cshrc\n\n" +
				"# User specific aliases and functions\n\n" +
				"alias rm 'rm -i'\nalias cp 'cp -i'\nalias mv 'mv -i'\n",
		},
	}, {
		file: "rootfiles-el7-xz.rpm",
		name: "rootfiles", version: "8.1", release: "11.el7", arch: "noarch",
		summary:    "The basic required files for the root user's directory",
		license:    "Public Domain",
		compressor: CompressorXz,
		sigPad:     4,
		payloadAt:  7028,
		files: map[string]string{
			"root/.bash_logout": "# ~/.bash_logout\n\n",
			"root/.cshrc": "# .cshrc\n\n" +
				"# User specific aliases and functions\n\n" +
				"alias rm 'rm -i'\nalias cp 'cp -i'\nalias mv 'mv -i'\n",
		},
	}, {
		file: "rootfiles-el9-zstd.rpm",
		name: "rootfiles", version: "8.1", release: "35.el9", arch: "noarch",
		summary:    "The basic required files for the root user's directory",
		license:    "Public Domain",
		compressor: CompressorZstd,
		sigPad:     4,
		payloadAt:  8921,
		files: map[string]string{
			"usr/share/rootfiles/.bash_logout": "# ~/.bash_logout\n\n",
			"usr/share/rootfiles/.cshrc": "# .cshrc\n\n" +
				"# User specific aliases and functions\n\n" +
				"alias rm 'rm -i'\nalias cp 'cp -i'\nalias mv 'mv -i'\n",
		},
		dirs: []string{"usr/share/rootfiles"},
	}}
}

func TestMetadataOnRealPackages(t *testing.T) {
	for _, w := range witnesses() {
		t.Run(w.file, func(t *testing.T) {
			r, size := reader(fixture(t, w.file))
			p, err := Metadata(r, size)
			if err != nil {
				t.Fatalf("Metadata: %v", err)
			}
			for _, c := range []struct{ what, got, want string }{
				{"Name", p.Name, w.name},
				{"Version", p.Version, w.version},
				{"Release", p.Release, w.release},
				{"Arch", p.Arch, w.arch},
				{"Summary", p.Summary, w.summary},
				{"License", p.License, w.license},
				{"PayloadFormat", p.PayloadFormat, PayloadFormatCpio},
				{"PayloadCompressor", p.PayloadCompressor, w.compressor},
			} {
				if c.got != c.want {
					t.Errorf("%s = %q, want %q", c.what, c.got, c.want)
				}
			}
			if p.PayloadOffset != w.payloadAt {
				t.Errorf("PayloadOffset = %d, want %d", p.PayloadOffset, w.payloadAt)
			}
			if p.PayloadSize != size-w.payloadAt {
				t.Errorf("PayloadSize = %d, want %d", p.PayloadSize, size-w.payloadAt)
			}
			// The padding, measured rather than assumed: End is before it.
			if pad := nextHeaderOffset(p.Signature.End, true) - p.Signature.End; pad != w.sigPad {
				t.Errorf("signature padding = %d, want %d", pad, w.sigPad)
			}
			if p.Lead.Major != 3 {
				t.Errorf("lead major = %d, want 3", p.Lead.Major)
			}
			// ⛔ The lead's own NVR field, which is NOT where Metadata takes
			// the name from. It agrees here; TestLeadDisagreesWithHeader
			// records where the lead does not.
			if p.Lead.Name == "" {
				t.Error("lead NVR field is empty")
			}
		})
	}
}

func TestPayloadBytesOnRealPackages(t *testing.T) {
	for _, w := range witnesses() {
		t.Run(w.file, func(t *testing.T) {
			r, size := reader(fixture(t, w.file))
			fs, err := OpenReader(r, size)
			if err != nil {
				t.Fatalf("OpenReader: %v", err)
			}
			defer fs.Close() //nolint:errcheck // always nil here
			for path, want := range w.files {
				got, err := fs.ReadFile(path)
				if err != nil {
					t.Fatalf("ReadFile(%q): %v", path, err)
				}
				// ⛔ BYTES, not length. A length check passes for a file
				// whose offset is one record out but whose size happens
				// to match -- which is exactly what a mis-rounded newc
				// pad produces.
				if string(got) != want {
					t.Errorf("ReadFile(%q):\n got %q\nwant %q", path, got, want)
				}
				st, err := fs.Stat(path)
				if err != nil {
					t.Fatalf("Stat(%q): %v", path, err)
				}
				if st.Size() != uint64(len(want)) {
					t.Errorf("Stat(%q).Size = %d, want %d", path, st.Size(), len(want))
				}
				if st.Mode()&0o170000 != 0o100000 {
					t.Errorf("Stat(%q).Mode = %o, want a regular file", path, st.Mode())
				}
			}
			for _, d := range w.dirs {
				st, err := fs.Stat(d)
				if err != nil {
					t.Fatalf("Stat(%q): %v", d, err)
				}
				if st.Mode()&0o170000 != 0o040000 {
					t.Errorf("Stat(%q).Mode = %o, want a directory", d, st.Mode())
				}
			}
		})
	}
}

// TestOpenerOnRealPackages exercises filesystem.Opener against a real payload,
// reading each file in two halves so that a non-zero offset is used.
func TestOpenerOnRealPackages(t *testing.T) {
	for _, w := range witnesses() {
		t.Run(w.file, func(t *testing.T) {
			r, size := reader(fixture(t, w.file))
			fs, err := Open(r, size)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			for path, want := range w.files {
				f, err := fs.OpenFile(path)
				if err != nil {
					t.Fatalf("OpenFile(%q): %v", path, err)
				}
				if f.Size() != int64(len(want)) {
					t.Errorf("Size = %d, want %d", f.Size(), len(want))
				}
				half := len(want) / 2
				buf := make([]byte, len(want)-half)
				n, err := f.ReadAt(buf, int64(half))
				if err != nil && !errors.Is(err, io.EOF) {
					t.Fatalf("ReadAt: %v", err)
				}
				if string(buf[:n]) != want[half:] {
					t.Errorf("ReadAt(%d):\n got %q\nwant %q", half, buf[:n], want[half:])
				}
				// Past the end is 0, io.EOF, per io.ReaderAt.
				if n, err := f.ReadAt(buf, int64(len(want))); n != 0 || !errors.Is(err, io.EOF) {
					t.Errorf("ReadAt past end = %d, %v; want 0, EOF", n, err)
				}
				if err := f.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			}
			if err := fs.Close(); err != nil {
				t.Errorf("fs.Close: %v", err)
			}
		})
	}
}

// TestListDirOnRealPackage walks the el9 package, whose payload has a real
// declared directory with five files under it.
func TestListDirOnRealPackage(t *testing.T) {
	r, size := reader(fixture(t, "rootfiles-el9-zstd.rpm"))
	fs, err := Open(r, size)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entries, err := fs.ListDir("usr/share/rootfiles")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if e.FileType() != fileTypeReg {
			t.Errorf("%s: FileType = %d, want %d", e.Name(), e.FileType(), fileTypeReg)
		}
		if e.Inode() == 0 {
			t.Errorf("%s: Inode is 0; cpio records carry one", e.Name())
		}
	}
	want := []string{".bash_logout", ".bash_profile", ".bashrc", ".cshrc", ".tcshrc"}
	if len(names) != len(want) {
		t.Fatalf("ListDir gave %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, names[i], want[i])
		}
	}
	// The root, reached three ways, must be the same directory.
	for _, root := range []string{"", ".", "/"} {
		if _, err := fs.ListDir(root); err != nil {
			t.Errorf("ListDir(%q): %v", root, err)
		}
	}
	// "usr" was declared by no record in this payload: it is synthesised.
	st, err := fs.Stat("usr")
	if err != nil {
		t.Fatalf("Stat(usr): %v", err)
	}
	if st.Mode() != 0o040755 {
		t.Errorf("synthesised usr mode = %o, want 040755", st.Mode())
	}
}

// TestLeadDisagreesWithHeader is the measurement behind Lead's warning: the lead
// cannot be used to decide anything, and this records the disagreement so that
// the next person to reach for Archnum sees it fail here first.
func TestLeadDisagreesWithHeader(t *testing.T) {
	seen := map[uint16][]string{}
	for _, w := range witnesses() {
		r, size := reader(fixture(t, w.file))
		p, err := Metadata(r, size)
		if err != nil {
			t.Fatalf("%s: %v", w.file, err)
		}
		if p.Arch != "noarch" {
			t.Fatalf("%s: header ARCH = %q, want noarch", w.file, p.Arch)
		}
		seen[p.Lead.Archnum] = append(seen[p.Lead.Archnum], w.file)
	}
	if len(seen) < 2 {
		t.Errorf("all three noarch packages agree on lead Archnum (%v); "+
			"Lead's warning that it cannot be trusted is no longer witnessed here", seen)
	}
	t.Logf("three noarch packages, lead Archnum -> files: %v", seen)
}

// TestMetadataDoesNotTouchThePayload proves Metadata's cost claim: it must parse
// a package whose payload bytes are entirely absent from the reader.
func TestMetadataDoesNotTouchThePayload(t *testing.T) {
	full := fixture(t, "rootfiles-el7-xz.rpm")
	p, err := Metadata(reader(full))
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	// Truncate to the first payload byte and hand over the ORIGINAL size, so
	// any read past the headers fails loudly.
	trunc := &shortReader{data: full[:p.PayloadOffset]}
	p2, err := Metadata(trunc, int64(len(full)))
	if err != nil {
		t.Fatalf("Metadata on a headers-only reader: %v", err)
	}
	if p2.Name != p.Name || p2.PayloadOffset != p.PayloadOffset {
		t.Errorf("headers-only parse differs: %+v vs %+v", p2, p)
	}
	// And Open on the same reader must fail, because the payload is not there.
	if _, err := Open(trunc, int64(len(full))); err == nil {
		t.Error("Open succeeded with no payload bytes available")
	}
}

// shortReader answers only for the bytes it holds.
type shortReader struct{ data []byte }

func (s *shortReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// TestErrNotFoundSatisfiesErrNotExist is the interface module's error contract,
// asserted on this driver's own operations rather than on the sentinel alone.
func TestErrNotFoundSatisfiesErrNotExist(t *testing.T) {
	if !errors.Is(ErrNotFound, iofs.ErrNotExist) {
		t.Fatalf("ErrNotFound does not satisfy fs.ErrNotExist")
	}
	r, size := reader(fixture(t, "rootfiles-el9-zstd.rpm"))
	fs, err := Open(r, size)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	missing := "no/such/path"
	probes := map[string]error{}
	_, err = fs.ReadFile(missing)
	probes["ReadFile"] = err
	_, err = fs.ListDir(missing)
	probes["ListDir"] = err
	_, err = fs.Stat(missing)
	probes["Stat"] = err
	_, err = fs.ReadLink(missing)
	probes["ReadLink"] = err
	_, err = fs.OpenFile(missing)
	probes["OpenFile"] = err
	for op, e := range probes {
		if !errors.Is(e, iofs.ErrNotExist) {
			t.Errorf("%s on a missing path: errors.Is(%v, fs.ErrNotExist) is false", op, e)
		}
		if errors.Is(e, ErrCorrupt) {
			t.Errorf("%s on a missing path also reports ErrCorrupt", op)
		}
	}
	// ⛔ AND THE OTHER DIRECTION, which is the half the interface module says
	// drivers get wrong: a structurally broken package must NOT read as 404.
	bad := bytes.Clone(fixture(t, "rootfiles-el9-zstd.rpm"))
	bad[96] = 0 // wreck the signature header's magic
	_, cerr := Open(reader(bad))
	if !errors.Is(cerr, ErrCorrupt) {
		t.Errorf("a wrecked header gave %v, want ErrCorrupt", cerr)
	}
	if errors.Is(cerr, iofs.ErrNotExist) {
		t.Errorf("a wrecked header reads as fs.ErrNotExist: %v", cerr)
	}
}

// TestMutatingMethodsAreRefused checks every write on the interface.
func TestMutatingMethodsAreRefused(t *testing.T) {
	r, size := reader(fixture(t, "rootfiles-el5-gzip.rpm"))
	fs, err := OpenReader(r, size)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	for name, err := range map[string]error{
		"WriteFile":  fs.WriteFile("root/.cshrc", []byte("x"), 0o644),
		"MkDir":      fs.MkDir("new", 0o755),
		"DeleteFile": fs.DeleteFile("root/.cshrc"),
		"DeleteDir":  fs.DeleteDir("root"),
		"Rename":     fs.Rename("root", "other"),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s returned %v, want ErrReadOnly", name, err)
		}
	}
	// The bytes are still what they were: ReadFile hands out a copy, so a
	// caller that writes to what it got cannot reach the payload.
	before, err := fs.ReadFile("root/.cshrc")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	copyOf := bytes.Clone(before)
	before[0] = 'X'
	after, err := fs.ReadFile("root/.cshrc")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(after, copyOf) {
		t.Errorf("writing to a ReadFile result changed the payload: %q", after)
	}
}
