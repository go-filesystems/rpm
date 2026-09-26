// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"fmt"
	iofs "io/fs"

	"github.com/go-filesystems/cpio"
)

// An RPM's payload is a cpio archive, and go-filesystems/cpio reads it.
//
// ⛔ This file used to hold a second copy of that reader -- newc only, about 220
// lines -- with a notice at the top naming the duplication and asking for exactly
// this. The cost it named was real: a defect fixed in one copy stayed present in the
// other, and one such defect was already on record in unarchive's comments (a next
// offset returned as zero, which looped for ever and reported a ten-minute timeout
// rather than a failure).
//
// What is left here is the mapping onto this package's own entry, plus posixMode,
// which is the direction the shared parser does not go.
//
// The parser now reads more than this copy did -- odc and the old binary variant in
// both byte orders, not just newc -- which costs nothing and is not relied on: an
// RPM payload is always newc, and rpm.go refuses any PayloadFormat that is not cpio
// before this is reached.

// entry is one file in the payload.
//
// ⛔ The name is CLEANED, because newFS stores it as the key of its index and
// cleanName is what a lookup goes through. go-filesystems/cpio returns the name as
// recorded -- "./etc/demo.conf" here, since rpmbuild writes the dot form -- and
// leaving it that way makes every lookup miss. Measured: seven tests said "path not
// found in payload" the moment the cleaning was dropped.
//
// It is the opposite of unarchive, which cleans inside newIndexFS. Each consumer
// cleans where its own index is built, and the parser stays out of it.
type entry struct {
	name string
	mode iofs.FileMode
	size int64
	off  int64 // where the data begins in the decompressed payload
	link string
	ino  uint64
}

// readCpio indexes the whole archive in payload.
//
// ⛔ RecordsExact, not Records. A payload”'s length is known exactly -- from the end
// of the header to the end of the file -- so a record that does not parse, a magic
// that is not one, and a missing trailer are all damage rather than the block padding
// an initramfs legitimately carries. Records tolerates all three, and using it here
// turned three of this package”'s refusals into silent successes: measured, when the
// local reader was first replaced.
//
// The payload is already in memory -- it is one compressed stream, so there is no
// reading it in parts -- which is why a bytes.Reader over it is the whole adaptation
// needed. unarchive hands the parser a file it keeps open instead, and that
// difference is why the two share the parser and not a filesystem.
func readCpio(payload []byte) ([]entry, error) {
	recs, err := cpio.RecordsExact(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		// ⛔ EVERY error becomes ErrCorrupt, not only the parser's two sentinels.
		// The reader here is a bytes.Reader over a payload already in memory, so a
		// read cannot fail and every error it can return is a verdict about the
		// bytes -- a field that is not a number among them, which is neither
		// ErrNotCpio nor ErrTruncated and was landing on a caller unwrapped.
		//
		// A caller of this package matches on ErrCorrupt and has never heard of
		// cpio's sentinels; letting one through would make it invisible.
		return nil, fmt.Errorf("rpm: payload: %s: %w", err, ErrCorrupt)
	}
	out := make([]entry, 0, len(recs))
	for _, r := range recs {
		out = append(out, entry{
			name: cleanName(r.Name),
			mode: r.Mode,
			size: r.Size,
			off:  r.Offset,
			link: r.Link,
			ino:  r.Inode,
		})
	}
	return out, nil
}
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
