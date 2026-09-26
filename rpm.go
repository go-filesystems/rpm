// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"fmt"
	"io"

	filesystem "github.com/go-filesystems/interface"
)

// Package is what an RPM says about itself.
//
// Every field here is taken from the MAIN HEADER and none from the lead, which is
// legacy and disagrees with the header about the architecture in two of this
// repository's three witnesses. Lead is kept so a caller can see what the lead
// claims, clearly labelled as its own.
type Package struct {
	Name    string
	Version string
	Release string
	Arch    string
	Summary string

	// Epoch is absent from most packages. rpm treats an absent epoch as 0 for
	// comparison but an ABSENT epoch and an epoch of 0 are distinguishable in
	// the header, so the flag says which this was rather than collapsing them.
	Epoch    int64
	HasEpoch bool

	License     string
	Description string
	Group       string
	OS          string
	Vendor      string
	Packager    string
	URL         string
	SourceRPM   string

	// PayloadFormat is PAYLOADFORMAT, almost always "cpio".
	PayloadFormat string
	// PayloadCompressor is PAYLOADCOMPRESSOR, or "gzip" for a package that
	// carries no such tag -- see payloadCompressor for why the default is
	// gzip and not "none".
	PayloadCompressor string

	// PayloadOffset is the first byte of the compressed payload: the byte
	// after the main header's data store, with NO padding. PayloadSize is
	// what is left of the file from there.
	PayloadOffset int64
	PayloadSize   int64

	// Lead, Signature and Header are the raw structures, for a caller that
	// wants a tag this type does not name.
	Lead      *Lead
	Signature *Header
	Header    *Header
}

// NEVRA is the canonical "name-[epoch:]version-release.arch" spelling.
func (p *Package) NEVRA() string {
	if p.HasEpoch {
		return fmt.Sprintf("%s-%d:%s-%s.%s", p.Name, p.Epoch, p.Version, p.Release, p.Arch)
	}
	return fmt.Sprintf("%s-%s-%s.%s", p.Name, p.Version, p.Release, p.Arch)
}

// Metadata reads the lead and both header structures and returns what the
// package says about itself. It does NOT touch the payload, so its cost is the
// size of the two headers -- a few kilobytes -- whatever the package weighs.
func Metadata(r io.ReaderAt, size int64) (*Package, error) {
	lead, err := readLead(r, size)
	if err != nil {
		return nil, err
	}
	sig, err := readHeader(r, size, leadSize, "signature")
	if err != nil {
		return nil, err
	}
	// ⛔ THE ASYMMETRIC RULE. The signature header IS padded to an 8-byte
	// boundary after its data store; the header proper is NOT. Passing false
	// here reads the second magic 0 to 7 bytes early and the error says
	// "header magic ... is 0x000000", which looks exactly like a corrupt
	// package and is not one. See nextHeaderOffset.
	hdrOff := nextHeaderOffset(sig.End, true)
	hdr, err := readHeader(r, size, hdrOff, "header")
	if err != nil {
		return nil, err
	}
	// ...and the payload starts at the header's End with NO rounding.
	payloadOff := nextHeaderOffset(hdr.End, false)
	epoch, hasEpoch := hdr.Int(TagEpoch)
	return &Package{
		Name:              hdr.String(TagName),
		Version:           hdr.String(TagVersion),
		Release:           hdr.String(TagRelease),
		Arch:              hdr.String(TagArch),
		Summary:           hdr.String(TagSummary),
		Epoch:             epoch,
		HasEpoch:          hasEpoch,
		License:           hdr.String(TagLicense),
		Description:       hdr.String(TagDescription),
		Group:             hdr.String(TagGroup),
		OS:                hdr.String(TagOS),
		Vendor:            hdr.String(TagVendor),
		Packager:          hdr.String(TagPackager),
		URL:               hdr.String(TagURL),
		SourceRPM:         hdr.String(TagSourceRPM),
		PayloadFormat:     hdr.String(TagPayloadFormat),
		PayloadCompressor: payloadCompressor(hdr),
		PayloadOffset:     payloadOff,
		PayloadSize:       size - payloadOff,
		Lead:              lead,
		Signature:         sig,
		Header:            hdr,
	}, nil
}

// Open reads an RPM's metadata AND decompresses its payload, returning the cpio
// contents as a filesystem.
//
// ⛔ The whole payload is decompressed into memory here, because an RPM payload
// is one compressed stream and no byte in it is reachable without decoding every
// byte before it. Budget for the INSTALLED size of the package. A caller that
// only wants the name and version should call Metadata, which reads the headers
// alone.
func Open(r io.ReaderAt, size int64) (*FS, error) {
	pkg, err := Metadata(r, size)
	if err != nil {
		return nil, err
	}
	// PAYLOADFORMAT is checked rather than assumed. rpm 5 could write "drpm"
	// for a delta package, whose payload is not a cpio at all; reading one as
	// cpio would fail with a bad-magic error naming cpio, which points at the
	// wrong thing.
	//
	// An ABSENT tag is accepted: packages older than the tag have a cpio
	// payload, exactly as they have a gzip one.
	if pkg.PayloadFormat != "" && pkg.PayloadFormat != PayloadFormatCpio {
		return nil, fmt.Errorf("rpm: payload format %q: %w", pkg.PayloadFormat, ErrUnsupported)
	}
	payload, err := decompressPayload(r, pkg.PayloadOffset, pkg.PayloadSize, pkg.PayloadCompressor)
	if err != nil {
		return nil, err
	}
	entries, err := readCpio(payload)
	if err != nil {
		return nil, err
	}
	return newFS(pkg, payload, entries), nil
}

// OpenReader is Open under the name every driver in go-filesystems answers to.
//
// github.com/go-filesystems/detect registers drivers as
// func(io.ReaderAt, int64) (filesystem.Filesystem, error); Open is the right
// shape but returns the concrete *FS, which is a different type and does not fit.
// A caller writes detect.Register(detect.RPM, rpm.OpenReader) and is done.
func OpenReader(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
	fs, err := Open(r, size)
	if err != nil {
		// ⛔ A typed nil inside an interface is NOT nil. Returning fs
		// directly on the error path hands the caller a non-nil
		// filesystem.Filesystem wrapping a nil *FS, so a caller that checks
		// the value rather than the error is told it has a filesystem and
		// panics on first use.
		return nil, err
	}
	return fs, nil
}
