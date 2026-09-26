// SPDX-License-Identifier: BSD-3-Clause

package rpm

// The tags this reader names. RPM defines several hundred; these are the ones
// something here reads, plus the few a caller most often wants next.
//
// The numbers are rpm's own (rpmtag.h). They are part of the on-disk format and
// cannot be renumbered, which is why they are written as literals rather than
// as an iota block: a tag's value is data, not a position in a list.
const (
	TagName        = 1000
	TagVersion     = 1001
	TagRelease     = 1002
	TagEpoch       = 1003
	TagSummary     = 1004
	TagDescription = 1005
	TagBuildTime   = 1006
	TagSize        = 1009
	TagVendor      = 1011
	TagLicense     = 1014
	TagPackager    = 1015
	TagGroup       = 1016
	TagURL         = 1020
	TagOS          = 1021
	TagArch        = 1022

	// TagFileSizes and its neighbours describe the payload's files in
	// PARALLEL ARRAYS -- one entry per file, in payload order. They are not
	// read here: the cpio payload carries the same facts and carries them
	// with the bytes, so reading them from the header would be a second
	// source that can disagree with the first.
	TagFileSizes = 1028
	TagFileModes = 1030
	TagFileNames = 1027 // retired in rpm 4; see TagBaseNames

	TagSourceRPM   = 1044
	TagArchiveSize = 1046
	TagBaseNames   = 1117
	TagDirNames    = 1118

	// TagPayloadFormat is very nearly always "cpio". rpm 5 could write
	// "drpm"; nothing this reader opens does.
	TagPayloadFormat = 1124
	// TagPayloadCompressor names the stream wrapped around the cpio:
	// "gzip", "bzip2", "xz", "zstd" or "none".
	//
	// ⛔ ITS ABSENCE IS NOT AN ERROR AND NOT "none". A package built before
	// rpm 4.0 carries no such tag and its payload is gzip: that is what
	// rpmlib's own default is, and treating a missing tag as an
	// uncompressed payload turns every pre-2000 package into a corrupt one.
	TagPayloadCompressor = 1125
	TagPayloadFlags      = 1126
)

// Signature-header tags. They share the numeric space with the main header's
// but mean different things in it, which is the reason the two headers are kept
// as separate values here instead of being merged into one tag map.
const (
	SigTagSize        = 1000 // size of the header + payload, in bytes
	SigTagMD5         = 1004
	SigTagGPG         = 1005
	SigTagPayloadSize = 1007
	SigTagSHA1        = 269
	SigTagSHA256      = 273
)
