// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path"
	"slices"
	"strings"

	filesystem "github.com/go-filesystems/interface"
)

// fileTypeReg, fileTypeDir and fileTypeLink are this org's DirEntry type codes
// (filesystem.NewDirEntry's third argument). unarchive's extract.go names
// fileTypeDir = 2 and tests against it, so the directory code is fixed by what
// the family already reads; the other two are given adjacent values for the
// callers that look at them.
const (
	fileTypeReg  uint8 = 1
	fileTypeDir  uint8 = 2
	fileTypeLink uint8 = 7
)

// FS is an opened RPM package seen as a filesystem: the cpio payload,
// decompressed, indexed by path.
//
// It satisfies filesystem.Filesystem and filesystem.Opener, and every mutating
// method returns ErrReadOnly.
type FS struct {
	pkg *Package
	// payload is the decompressed cpio archive. Every entry's bytes are a
	// slice of it, which is what makes Opener honest here: the data is
	// already resident, so a ReadAt at any offset costs a copy and nothing
	// more.
	payload []byte
	byName  map[string]*entry
	kids    map[string][]string
}

// Package returns the metadata of the package this filesystem came from, so a
// caller that opened the payload does not have to parse the headers twice.
func (f *FS) Package() *Package { return f.pkg }

// newFS indexes the payload entries.
//
// ⛔ PARENT DIRECTORIES NOTHING DECLARED ARE SYNTHESISED. An RPM usually lists
// its directories -- all three witnesses in testdata do -- but it is not obliged
// to, and a payload holding only "usr/lib/tmpfiles.d/rootfiles.conf" would
// otherwise have an empty root and be unwalkable. The synthesis runs AFTER the
// real entries are filed, so a declared directory keeps its own mode and mtime.
func newFS(pkg *Package, payload []byte, entries []entry) *FS {
	f := &FS{
		pkg:     pkg,
		payload: payload,
		byName:  make(map[string]*entry, len(entries)),
		kids:    make(map[string][]string, len(entries)),
	}
	for i := range entries {
		e := entries[i]
		if e.name == "" || e.name == "." {
			continue
		}
		f.byName[e.name] = &e
		f.link(e.name)
	}
	for name := range f.byName {
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			if _, ok := f.byName[dir]; ok {
				break
			}
			f.byName[dir] = &entry{name: dir, mode: iofs.ModeDir | 0o755}
			f.link(dir)
		}
	}
	return f
}

// link files a name under its parent, once.
func (f *FS) link(name string) {
	dir := path.Dir(name)
	if !slices.Contains(f.kids[dir], name) {
		f.kids[dir] = append(f.kids[dir], name)
	}
}

// cleanName is the ONE spelling of a path this index uses, and every lookup goes
// through it.
//
// ⛔ A cpio payload's names begin with "./" -- all three witnesses do, for every
// record -- while a caller asks for "/root/.bashrc" or "root/.bashrc". Three
// spellings of one path is three chances to miss, so both sides are normalised
// to the same one: no leading slash, no leading "./", no trailing slash, path
// cleaned. The root is "." on both sides.
func cleanName(name string) string {
	name = strings.TrimPrefix(name, "./")
	name = path.Clean("/" + name)
	return strings.TrimPrefix(name, "/")
}

// lookup resolves a caller's path to an entry.
func (f *FS) lookup(op, p string) (*entry, error) {
	name := cleanName(p)
	if name == "." || name == "" {
		return &entry{name: ".", mode: iofs.ModeDir | 0o755}, nil
	}
	e, ok := f.byName[name]
	if !ok {
		return nil, fmt.Errorf("rpm: %s %q: %w", op, p, ErrNotFound)
	}
	return e, nil
}

// Close releases nothing: the payload is a byte slice and the io.ReaderAt it was
// read from belongs to the caller. It is here because filesystem.Filesystem asks
// for it, and it returns nil rather than pretending to a flush it does not do.
func (f *FS) Close() error { return nil }

// ReadFile returns the whole contents of a regular file in the payload.
func (f *FS) ReadFile(p string) ([]byte, error) {
	e, err := f.lookup("read", p)
	if err != nil {
		return nil, err
	}
	if !e.mode.IsRegular() {
		return nil, fmt.Errorf("rpm: read %q (mode %s): %w", p, e.mode, ErrNotRegular)
	}
	// A copy, not a slice of the payload: the caller owns what it gets back
	// and must not be able to rewrite this filesystem by writing to it.
	return bytes.Clone(f.payload[e.off : e.off+e.size]), nil
}

// ListDir lists one directory. The root is "", "." or "/".
func (f *FS) ListDir(p string) ([]filesystem.DirEntry, error) {
	e, err := f.lookup("readdir", p)
	if err != nil {
		return nil, err
	}
	if !e.mode.IsDir() {
		return nil, fmt.Errorf("rpm: readdir %q (mode %s): %w", p, e.mode, ErrNotRegular)
	}
	names := slices.Clone(f.kids[e.name])
	slices.Sort(names)
	out := make([]filesystem.DirEntry, 0, len(names))
	for _, n := range names {
		kid := f.byName[n]
		out = append(out, filesystem.NewDirEntry(kid.ino, path.Base(n), dirEntryType(kid.mode)))
	}
	return out, nil
}

func dirEntryType(m iofs.FileMode) uint8 {
	switch {
	case m.IsDir():
		return fileTypeDir
	case m&iofs.ModeSymlink != 0:
		return fileTypeLink
	default:
		return fileTypeReg
	}
}

// Stat reports mode, size and inode for a path.
func (f *FS) Stat(p string) (filesystem.Stat, error) {
	e, err := f.lookup("stat", p)
	if err != nil {
		return nil, err
	}
	return filesystem.NewStat(posixMode(e.mode), uint64(e.size), e.ino), nil
}

// ReadLink returns a symlink's target, as the payload stored it. The target is
// not resolved: a relative target stays relative.
func (f *FS) ReadLink(p string) (string, error) {
	e, err := f.lookup("readlink", p)
	if err != nil {
		return "", err
	}
	if e.mode&iofs.ModeSymlink == 0 {
		return "", fmt.Errorf("rpm: readlink %q (mode %s): %w", p, e.mode, ErrNotRegular)
	}
	return e.link, nil
}

// OpenFile satisfies filesystem.Opener.
//
// It is implemented, rather than left out, because the payload is already
// resident: decompressPayload had to materialise the whole cpio to reach any of
// it, so a byte range costs a copy. The interface module's own guidance is that a
// driver which cannot answer a range without decoding everything before it should
// NOT implement Opener -- the decoding here happens once, at open, and is
// accounted for there rather than hidden inside each read.
func (f *FS) OpenFile(p string) (filesystem.File, error) {
	e, err := f.lookup("open", p)
	if err != nil {
		return nil, err
	}
	if !e.mode.IsRegular() {
		return nil, fmt.Errorf("rpm: open %q (mode %s): %w", p, e.mode, ErrNotRegular)
	}
	return &file{
		SectionReader: io.NewSectionReader(bytes.NewReader(f.payload), e.off, e.size),
		size:          e.size,
	}, nil
}

// file is one payload member open for random access. io.SectionReader already
// implements io.ReaderAt to the letter -- short reads only with an error, EOF at
// the end, no shared seek position, safe concurrently -- which is the whole of
// what filesystem.File asks for.
type file struct {
	*io.SectionReader
	size int64
}

func (h *file) Size() int64  { return h.size }
func (h *file) Close() error { return nil }

// The mutating half of filesystem.Filesystem. An RPM's headers carry digests
// over the bytes that follow them and its payload is a single compressed stream,
// so there is no in-place write that leaves a valid package behind.
func (f *FS) WriteFile(string, []byte, os.FileMode) error { return ErrReadOnly }
func (f *FS) MkDir(string, os.FileMode) error             { return ErrReadOnly }
func (f *FS) DeleteFile(string) error                     { return ErrReadOnly }
func (f *FS) DeleteDir(string) error                      { return ErrReadOnly }
func (f *FS) Rename(string, string) error                 { return ErrReadOnly }
