// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// headerMagic is the three bytes each of the two header structures begins with.
// There is no fourth byte: the version is a separate u8 immediately after it,
// which is why this is a 3-byte magic and not a 4-byte one.
var headerMagic = [3]byte{0x8E, 0xAD, 0xE8}

// headerPrefix is magic(3) + version(1) + reserved(4) + nindex(4) + hsize(4).
const headerPrefix = 16

// indexEntrySize is the width of one index entry: tag, type, offset, count,
// each a big-endian u32.
const indexEntrySize = 16

// maxIndex and maxData bound what this reader will allocate for one header
// before deciding the counts are not credible. rpm's own limits are 64 MiB of
// data and 64 Ki entries per header (HEADER_DATA_MAX / hdrblobRead); these are
// generous against that and stop a truncated or hostile file from asking for
// gigabytes on the strength of two u32s.
const (
	maxIndex = 1 << 20
	maxData  = 1 << 28
)

// Type is an index entry's value type, as stored in the entry's second u32.
type Type uint32

// The ten index types. RPM has never added an eleventh.
const (
	TypeNull Type = iota
	TypeChar
	TypeInt8
	TypeInt16
	TypeInt32
	TypeInt64
	TypeString
	TypeBin
	TypeStringArray
	TypeI18NString
)

// Entry is one 16-byte index entry: which tag, of what type, where in the
// header's data store, and how many of them.
type Entry struct {
	Tag    uint32
	Type   Type
	Offset uint32
	Count  uint32
}

// Header is one of an RPM's two header structures: the signature, or the header
// proper. Both have exactly this shape, which is why one parser reads both.
//
// The data store is held whole. A header is at most a few kilobytes -- the
// largest in this repository's witnesses is 4.8 KiB -- so copying it once buys
// accessors that cannot fail and need no io.ReaderAt of their own.
type Header struct {
	Version uint8
	// Entries are in the order the file lists them, which is rpm's own tag
	// order and is therefore sorted ascending in every package measured.
	// Nothing here relies on that.
	Entries []Entry

	// Offset is where this header's magic sits in the file, and End is the
	// first byte after its data store -- BEFORE any alignment padding. The
	// padding is the caller's business because only the signature header has
	// it; see nextHeaderOffset.
	Offset, End int64

	byTag map[uint32]Entry
	data  []byte
}

// readHeader parses the header structure whose magic sits at off.
func readHeader(r io.ReaderAt, size, off int64, what string) (*Header, error) {
	if off < 0 || off+headerPrefix > size {
		return nil, fmt.Errorf("rpm: the %s header would start at %d of %d bytes: %w",
			what, off, size, ErrCorrupt)
	}
	var pre [headerPrefix]byte
	if _, err := r.ReadAt(pre[:], off); err != nil {
		return nil, fmt.Errorf("rpm: reading the %s header at %d: %w", what, off, err)
	}
	if [3]byte(pre[0:3]) != headerMagic {
		// ⛔ THE MESSAGE NAMES WHICH HEADER, and that is not decoration.
		// The single most likely cause of this error is the 8-byte padding
		// after the signature header's data: skip it and the *header* magic
		// is missing, apply it where it does not belong and the *signature*
		// magic is. Which of the two is named tells those apart at a glance.
		return nil, fmt.Errorf("rpm: %s header magic at %d is %#x, want %#x: %w",
			what, off, pre[0:3], headerMagic[:], ErrCorrupt)
	}
	nindex := binary.BigEndian.Uint32(pre[8:12])
	hsize := binary.BigEndian.Uint32(pre[12:16])
	if nindex > maxIndex || hsize > maxData {
		return nil, fmt.Errorf("rpm: %s header claims %d entries and %d data bytes: %w",
			what, nindex, hsize, ErrCorrupt)
	}
	idxLen := int64(nindex) * indexEntrySize
	end := off + headerPrefix + idxLen + int64(hsize)
	if end > size {
		return nil, fmt.Errorf(
			"rpm: %s header ends at %d, past the %d bytes of the file: %w",
			what, end, size, ErrCorrupt)
	}
	body := make([]byte, idxLen+int64(hsize))
	if _, err := r.ReadAt(body, off+headerPrefix); err != nil {
		return nil, fmt.Errorf("rpm: reading the %s header body at %d: %w", what, off, err)
	}
	h := &Header{
		Version: pre[3],
		Entries: make([]Entry, 0, nindex),
		Offset:  off,
		End:     end,
		byTag:   make(map[uint32]Entry, nindex),
		data:    body[idxLen:],
	}
	for i := range int64(nindex) {
		raw := body[i*indexEntrySize:]
		e := Entry{
			// ⛔ BIG-ENDIAN, all four fields, in a format whose
			// overwhelming majority of readers and writers are
			// little-endian machines. Reading these with
			// binary.LittleEndian does not fail here: it yields a tag
			// of 0xE8030000 for NAME and an offset in the hundreds of
			// millions, so the failure surfaces as "tag 1000 is not in
			// this header" -- a missing name, not a byte-order fault.
			Tag:    binary.BigEndian.Uint32(raw[0:4]),
			Type:   Type(binary.BigEndian.Uint32(raw[4:8])),
			Offset: binary.BigEndian.Uint32(raw[8:12]),
			Count:  binary.BigEndian.Uint32(raw[12:16]),
		}
		if err := h.check(e, what); err != nil {
			return nil, err
		}
		h.Entries = append(h.Entries, e)
		// First writing wins. rpm does not emit a tag twice; if one ever
		// does, the first is what rpmlib's own binary search finds.
		if _, dup := h.byTag[e.Tag]; !dup {
			h.byTag[e.Tag] = e
		}
	}
	return h, nil
}

// check proves an entry's value lies inside the data store, so that every
// accessor below can be total.
//
// Validating here rather than in the accessors is a deliberate trade: a header
// with one impossible entry is refused whole, instead of answering "" for that
// tag and leaving the caller to wonder whether the tag was absent or the file
// was broken. Absent and broken are different answers and only one of them
// deserves silence.
func (h *Header) check(e Entry, what string) error {
	fail := func(why string) error {
		return fmt.Errorf("rpm: %s header tag %d (type %d, offset %d, count %d) %s: %w",
			what, e.Tag, e.Type, e.Offset, e.Count, why, ErrCorrupt)
	}
	if int64(e.Offset) > int64(len(h.data)) {
		return fail("starts past the data store")
	}
	rest := h.data[e.Offset:]
	switch e.Type {
	case TypeNull:
		return nil
	case TypeChar, TypeInt8, TypeBin:
		return fixedExtent(e, rest, 1, fail)
	case TypeInt16:
		return fixedExtent(e, rest, 2, fail)
	case TypeInt32:
		return fixedExtent(e, rest, 4, fail)
	case TypeInt64:
		return fixedExtent(e, rest, 8, fail)
	case TypeString, TypeI18NString, TypeStringArray:
		// A string's length is not in the entry: it is however far away
		// the next NUL is. Count says how MANY strings follow, one after
		// another, and a string type with count 0 carries nothing.
		for range e.Count {
			i := bytes.IndexByte(rest, 0)
			if i < 0 {
				return fail("has an unterminated string")
			}
			rest = rest[i+1:]
		}
		return nil
	default:
		return fail("has a type this reader does not know")
	}
}

// fixedExtent proves Count values of the given width fit in what is left of the
// data store.
func fixedExtent(e Entry, rest []byte, width int, fail func(string) error) error {
	if int64(e.Count)*int64(width) > int64(len(rest)) {
		return fail("runs past the end of the data store")
	}
	return nil
}

// nextHeaderOffset is where the header AFTER this one begins, given whether
// this one is padded.
//
// ⛔ THE ONE RULE IN THIS FORMAT THAT IS ASYMMETRIC. The signature header's data
// store is followed by 0 to 7 bytes of zero padding, so that the header proper
// starts on an 8-byte boundary; the header proper is NOT padded, and the payload
// begins at the byte after its data store.
//
// Measured on this repository's three witnesses: the el7 and el9 packages need
// 4 bytes of padding, and the el5 one needs NONE -- its signature data happened
// to end at 440, already a multiple of 8. So a reader that omits the padding
// altogether opens the el5 package perfectly and fails on the other two, and one
// tested against a single pre-2000 package would ship the bug. That is recorded
// in the ablation table in README.md, because it is the reason the witness set
// spans three build eras rather than being one small file.
func nextHeaderOffset(end int64, padded bool) int64 {
	if !padded {
		return end
	}
	return (end + 7) &^ 7
}

// Has says whether the header carries the tag at all.
func (h *Header) Has(tag uint32) bool {
	_, ok := h.byTag[tag]
	return ok
}

// Lookup returns the index entry for a tag.
func (h *Header) Lookup(tag uint32) (Entry, bool) {
	e, ok := h.byTag[tag]
	return e, ok
}

// String returns the first string stored under tag, or "" if the tag is absent
// or holds something that is not a string.
//
// "" for an absent tag is the right default HERE and would not be everywhere:
// every string tag this package reads is one whose absence and whose emptiness
// mean the same thing to a caller (no summary, no license, no compressor named).
// The one tag where that is false -- PAYLOADCOMPRESSOR, whose absence means gzip
// and not "no compression" -- is read through Has first. See payloadCompressor.
func (h *Header) String(tag uint32) string {
	s := h.Strings(tag)
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// Strings returns every string stored under tag. A STRING or I18NSTRING yields
// at most one; a STRING_ARRAY yields Count of them.
func (h *Header) Strings(tag uint32) []string {
	e, ok := h.byTag[tag]
	if !ok {
		return nil
	}
	switch e.Type {
	case TypeString, TypeI18NString, TypeStringArray:
	default:
		return nil
	}
	rest := h.data[e.Offset:]
	out := make([]string, 0, e.Count)
	for range e.Count {
		i := bytes.IndexByte(rest, 0)
		// check() proved the terminator is there for every one of them.
		out = append(out, string(rest[:i]))
		rest = rest[i+1:]
	}
	return out
}

// Ints returns every integer stored under tag, widened to int64. CHAR and INT8
// count as integers here; BIN does not, because a BIN entry is a digest or a
// blob and reading it as numbers is never what a caller meant.
func (h *Header) Ints(tag uint32) []int64 {
	e, ok := h.byTag[tag]
	if !ok {
		return nil
	}
	var width int
	switch e.Type {
	case TypeChar, TypeInt8:
		width = 1
	case TypeInt16:
		width = 2
	case TypeInt32:
		width = 4
	case TypeInt64:
		width = 8
	default:
		return nil
	}
	rest := h.data[e.Offset:]
	out := make([]int64, 0, e.Count)
	for i := range int(e.Count) {
		b := rest[i*width : (i+1)*width]
		var v int64
		switch width {
		case 1:
			v = int64(int8(b[0]))
		case 2:
			v = int64(int16(binary.BigEndian.Uint16(b)))
		case 4:
			v = int64(int32(binary.BigEndian.Uint32(b)))
		default:
			v = int64(binary.BigEndian.Uint64(b))
		}
		out = append(out, v)
	}
	return out
}

// Int returns the first integer stored under tag, and whether there was one.
func (h *Header) Int(tag uint32) (int64, bool) {
	v := h.Ints(tag)
	if len(v) == 0 {
		return 0, false
	}
	return v[0], true
}

// Bytes returns the raw value stored under a BIN or CHAR tag -- a digest, a
// signature, a blob. The slice aliases the header's own copy of the data store
// and must not be written to.
func (h *Header) Bytes(tag uint32) []byte {
	e, ok := h.byTag[tag]
	if !ok {
		return nil
	}
	switch e.Type {
	case TypeBin, TypeChar, TypeInt8:
		return h.data[e.Offset : int64(e.Offset)+int64(e.Count)]
	default:
		return nil
	}
}
