// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"fmt"
	iofs "io/fs"
	"strconv"
	"strings"
	"time"
)

// ⛔⛔ THIS FILE DUPLICATES github.com/go-filesystems/unarchive's cpio.go AND
// indexfs.go, AND THAT DUPLICATION IS DELIBERATE, NAMED, AND MEANT TO BE
// REMOVED.
//
// unarchive (v0.7.0) already reads newc, crc and odc cpio, and already turns the
// resulting records into an io/fs.FS with directory synthesis, Stat, ReadLink and
// a read-only filesystem.Filesystem adapter over it. All of that is unexported:
// openCpio, record, newIndexFS, FromFS's internals. This package therefore
// cannot call it, and depending on unarchive would mean waiting on an export.
//
// What is copied here is deliberately SMALLER than what it copies from, because
// an RPM payload is always newc:
//
//   - newc only. odc and the byte-order-dependent "old binary" variant are not
//     read, and the CRC variant (070702) is accepted as newc because it differs
//     only in a checksum field this reader does not verify.
//   - No format sniffing, no trailing-block tolerance: the payload's length is
//     known exactly, from the end of the header to the end of the file.
//
// THE CONSOLIDATION: export unarchive's record/newIndexFS (or a small
// `unarchive/cpio` subpackage carrying openCpio plus the index), and delete this
// file together with fs.go's index. Until then, a defect fixed in one copy is
// still present in the other -- and one such defect is already recorded in
// unarchive's own comments (cpioRecord's `next` returned as zero, which loops for
// ever rather than failing). The equivalent line here is nextOff, and it is a
// return value for the same reason.
//
// This notice is repeated in doc.go and README.md so that it is visible without
// reading the source.

// The two newc magics. 070702 is newc with the checksum field filled in; the
// layout is identical, so it is read as newc.
const (
	cpioNewc = "070701"
	cpioCRC  = "070702"
	// cpioTrailer is the name of the sentinel record that ends every archive.
	cpioTrailer = "TRAILER!!!"
	// cpioHeaderLen is newc's fixed header: a 6-byte magic and 13 fields of
	// 8 hex digits each.
	cpioHeaderLen = 110
)

// entry is one payload member: where its bytes are in the decompressed payload,
// and what the archive said about it.
type entry struct {
	name  string // cleaned, slash-separated, no leading "./"
	mode  iofs.FileMode
	size  int64
	off   int64 // where the data begins in the decompressed payload
	link  string
	mtime time.Time
	ino   uint64
}

// readCpio indexes the whole newc archive in payload.
func readCpio(payload []byte) ([]entry, error) {
	var out []entry
	off := int64(0)
	size := int64(len(payload))
	for {
		e, nextOff, done, err := readCpioRecord(payload, size, off)
		if err != nil {
			return nil, err
		}
		if done {
			return out, nil
		}
		out = append(out, *e)
		// ⛔ nextOff is a RETURN VALUE and the loop's only advance. The same
		// shape in unarchive once came back as zero, which re-read record
		// one for ever: the suite reported a TIMEOUT rather than a failure,
		// so there was nothing pointing at this line. A zero here would do
		// the same, which is why readCpioRecord computes it before it can
		// return successfully at all.
		off = nextOff
	}
}

// readCpioRecord reads one header. done is true at the trailer or at the end.
func readCpioRecord(p []byte, size, off int64) (e *entry, nextOff int64, done bool, err error) {
	if off+cpioHeaderLen > size {
		// Reaching the end without a trailer is a truncated payload. rpm
		// always writes one, so this is not the normal exit.
		return nil, 0, false, fmt.Errorf(
			"rpm: cpio header at %d runs past the %d-byte payload: %w", off, size, ErrCorrupt)
	}
	h := p[off : off+cpioHeaderLen]
	magic := string(h[0:6])
	if magic != cpioNewc && magic != cpioCRC {
		return nil, 0, false, fmt.Errorf(
			"rpm: cpio magic at %d is %q, want %q (an RPM payload is always newc): %w",
			off, magic, cpioNewc, ErrCorrupt)
	}
	// The thirteen fields, in order: ino mode uid gid nlink mtime filesize
	// devmajor devminor rdevmajor rdevminor namesize check.
	field := func(i int) (int64, error) {
		v, ferr := strconv.ParseInt(string(h[6+i*8:14+i*8]), 16, 64)
		if ferr != nil {
			return 0, fmt.Errorf("rpm: cpio field %d at %d: %w: %w", i, off, ferr, ErrCorrupt)
		}
		return v, nil
	}
	ino, err := field(0)
	if err != nil {
		return nil, 0, false, err
	}
	mode, err := field(1)
	if err != nil {
		return nil, 0, false, err
	}
	mtime, err := field(5)
	if err != nil {
		return nil, 0, false, err
	}
	fileSize, err := field(6)
	if err != nil {
		return nil, 0, false, err
	}
	nameSize, err := field(11)
	if err != nil {
		return nil, 0, false, err
	}
	if nameSize <= 0 || off+cpioHeaderLen+nameSize > size {
		return nil, 0, false, fmt.Errorf("rpm: cpio name at %d is %d bytes: %w",
			off, nameSize, ErrCorrupt)
	}
	name := strings.TrimRight(string(p[off+cpioHeaderLen:off+cpioHeaderLen+nameSize]), "\x00")
	// ⛔ newc pads BOTH the name and the data up to a multiple of four, and
	// both paddings are measured from the START OF THE HEADER rather than
	// from the start of the field. Rounding the wrong origin puts every
	// later record one to three bytes out, and the failure then reads as a
	// bad magic somewhere in the middle of the archive.
	dataOff := round4(off + cpioHeaderLen + nameSize)
	nextOff = round4(dataOff + fileSize)
	if name == cpioTrailer {
		return nil, nextOff, true, nil
	}
	if fileSize < 0 || dataOff+fileSize > size {
		return nil, 0, false, fmt.Errorf("rpm: cpio %q claims %d bytes at %d, past the %d-byte payload: %w",
			name, fileSize, dataOff, size, ErrCorrupt)
	}
	e = &entry{
		name:  cleanName(name),
		mode:  cpioMode(mode),
		size:  fileSize,
		off:   dataOff,
		mtime: time.Unix(mtime, 0).UTC(),
		ino:   uint64(ino),
	}
	// A symlink's TARGET IS ITS DATA, and filesize is the target's length.
	// It is read now because an entry carries the target, not an offset.
	if e.mode&iofs.ModeSymlink != 0 {
		e.link = strings.TrimRight(string(p[dataOff:dataOff+fileSize]), "\x00")
		e.size = 0
	}
	return e, nextOff, false, nil
}

// round4 rounds up to the next multiple of four.
func round4(n int64) int64 { return (n + 3) &^ 3 }

// cpioMode turns a POSIX st_mode into an iofs.FileMode.
//
// ⛔ The type lives in the HIGH OCTAL DIGITS of st_mode and nowhere near
// iofs.FileMode's own type bits: S_IFDIR is 0o040000 while iofs.ModeDir is
// 1<<31. Narrowing one into the other without this switch leaves every directory
// looking like a regular file with unusual permissions -- and a payload's
// directories are most of what an RPM carries.
func cpioMode(m int64) iofs.FileMode {
	mode := iofs.FileMode(m & 0o777)
	switch m & 0o170000 {
	case 0o040000:
		mode |= iofs.ModeDir
	case 0o120000:
		mode |= iofs.ModeSymlink
	case 0o010000:
		mode |= iofs.ModeNamedPipe
	case 0o020000:
		mode |= iofs.ModeDevice | iofs.ModeCharDevice
	case 0o060000:
		mode |= iofs.ModeDevice
	case 0o140000:
		mode |= iofs.ModeSocket
	}
	return mode
}

// posixMode is the inverse: the st_mode a filesystem.Stat carries. It matters
// because filesystem.Stat.Mode is a uint16, so the type bits have to be back in
// their octal places or a caller cannot tell a directory from a file.
func posixMode(m iofs.FileMode) uint16 {
	out := uint16(m.Perm())
	switch {
	case m&iofs.ModeDir != 0:
		out |= 0o040000
	case m&iofs.ModeSymlink != 0:
		out |= 0o120000
	case m&iofs.ModeNamedPipe != 0:
		out |= 0o010000
	case m&iofs.ModeCharDevice != 0:
		out |= 0o020000
	case m&iofs.ModeDevice != 0:
		out |= 0o060000
	case m&iofs.ModeSocket != 0:
		out |= 0o140000
	default:
		out |= 0o100000
	}
	return out
}
