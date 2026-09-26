// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// leadSize is the fixed length of the lead, in bytes. Every field below is at a
// constant offset inside it and the whole thing is big-endian.
const leadSize = 96

// leadMagic is the four bytes an RPM begins with: 0xED 0xAB 0xEE 0xDB.
var leadMagic = [4]byte{0xED, 0xAB, 0xEE, 0xDB}

// Lead is the 96-byte prologue of every RPM package.
//
// ⛔ IT IS LEGACY AND ITS FIELDS ARE NOT TO BE TRUSTED. rpm stopped maintaining
// the lead in 2000 and keeps writing it only so that file(1) and older tools
// still recognise a package. The measured witnesses in this repository show why
// reading anything but the magic out of it is a mistake: `Archnum` is 255 in
// both the el5 and el9 noarch packages and 1 in the el7 one, for three packages
// whose ARCH tag says "noarch" in all three. A caller that decided the
// architecture from the lead would get a different answer per build era for the
// same package.
//
// So this type exists to be VALIDATED (the magic) and EXPOSED (for a tool that
// wants to show what the lead claims), and Metadata takes every fact it
// reports, architecture included, from the main header instead.
type Lead struct {
	Major uint8 // 3 in every package rpm has written since 1997
	Minor uint8
	// Type is 0 for a binary package and 1 for a source package.
	Type uint16
	// Archnum is a number from rpm's own table, not a Linux machine type.
	Archnum uint16
	// Name is the 66-byte NUL-padded "name-version-release" field, trimmed.
	// It is truncated, not wrapped, for a package whose NVR is longer.
	Name    string
	Osnum   uint16
	SigType uint16 // 5 for the header-structure signature used since rpm 2.1
}

// readLead reads and validates the lead at offset 0.
//
// It checks the magic and nothing else, on purpose: a lead whose Major says 4,
// or whose Archnum is a number no table lists, still precedes a package rpm
// itself will install, and refusing it here would reject packages that work.
func readLead(r io.ReaderAt, size int64) (*Lead, error) {
	if size < leadSize {
		return nil, fmt.Errorf("rpm: %d bytes is shorter than the 96-byte lead: %w", size, ErrNotRPM)
	}
	var buf [leadSize]byte
	if _, err := r.ReadAt(buf[:], 0); err != nil {
		return nil, fmt.Errorf("rpm: reading the lead: %w", err)
	}
	if [4]byte(buf[0:4]) != leadMagic {
		return nil, fmt.Errorf("rpm: lead magic is %#x, want %#x: %w",
			buf[0:4], leadMagic[:], ErrNotRPM)
	}
	return &Lead{
		Major:   buf[4],
		Minor:   buf[5],
		Type:    binary.BigEndian.Uint16(buf[6:8]),
		Archnum: binary.BigEndian.Uint16(buf[8:10]),
		Name:    strings.TrimRight(string(buf[10:76]), "\x00"),
		Osnum:   binary.BigEndian.Uint16(buf[76:78]),
		SigType: binary.BigEndian.Uint16(buf[78:80]),
	}, nil
	// buf[80:96] is reserved and has been zero in every package measured.
}
