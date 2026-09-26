// SPDX-License-Identifier: BSD-3-Clause

// Package rpm reads RPM packages: their metadata, and their cpio payload as a
// filesystem.
//
// It is pure Go, CGO-free, and depends on no rpm library. Two entry points:
//
//	func Metadata(r io.ReaderAt, size int64) (*Package, error)
//	func OpenReader(r io.ReaderAt, size int64) (filesystem.Filesystem, error)
//
// Metadata reads the lead and the two header structures and stops; its cost is a
// few kilobytes whatever the package weighs. OpenReader additionally decompresses
// the payload and returns it as a github.com/go-filesystems/interface
// Filesystem. Open is OpenReader with the concrete *FS, for a caller that wants
// Package() or the optional interfaces by name.
//
// The filesystem is READ-ONLY: every mutating method returns ErrReadOnly. The
// optional filesystem.Opener is implemented, so a caller can read a byte range of
// one payload file without materialising it; see FS.OpenFile for why that is
// honest here and would not be for a driver that streamed.
//
// # The format, and the one rule that catches everyone
//
// A .rpm is: a 96-byte lead, a signature header structure, the header proper,
// then the payload. Everything is big-endian. Each header structure is a 3-byte
// magic, a version, four reserved bytes, an entry count, a data size, that many
// 16-byte index entries, and that many bytes of data store.
//
// ⛔ THE SIGNATURE HEADER'S DATA STORE IS PADDED TO AN 8-BYTE BOUNDARY AND THE
// HEADER PROPER'S IS NOT. Getting this wrong lands 1 to 7 bytes inside the second
// magic and the error reads as a corrupt package. It is asymmetric, it is easy to
// apply in the wrong place, and -- measured here -- it is invisible to a
// substantial minority of real packages, whose signature data happens to end
// 8-aligned already. See nextHeaderOffset and README.md's ablation table.
//
// # The cpio reader comes from go-filesystems/cpio
//
// The payload is a cpio archive and github.com/go-filesystems/cpio parses it. This
// package used to carry a second copy of that parser -- newc only, about 220 lines --
// with a notice here saying so and asking for exactly this consolidation. The cost it
// named was real: a defect fixed in one copy stayed present in the other.
//
// What stays here is the mapping onto this package's entry, the index in fs.go, and
// posixMode, which is the direction the shared parser does not go. The FILESYSTEM is
// deliberately not shared: a payload is one compressed stream, so it is in memory and
// entries are sections of it, while unarchive indexes into a file it keeps open.
//
// It calls cpio.RecordsExact rather than cpio.Records. A payload's length is known
// exactly, so a record that does not parse, a magic that is not one, and a missing
// trailer are all damage -- not the block padding an initramfs legitimately carries.
// Records tolerates all three, and using it here turned three of this package's
// refusals into silent successes, which is how that distinction was found.
//
// Two things the consolidation settled, both of them disagreements between the two
// readers that no test on either side could see:
//
//   - the shared parser checks EVERY numeric header field. This package did; the
//     other ignored the errors on inode and mtime, so a header with a non-hex inode
//     parsed to inode 0 and looked ordinary.
//   - the inode is carried, because this package reports it in Stat. It is NOT
//     portable across cpio variants: odc's field and the old binary variant's are too
//     narrow to hold a real one, and cpio(1) renumbers them 1..n.
//
// # ⚠⚠ WHERE THE WITNESSES COME FROM, AND WHAT THEY CANNOT SHOW
//
// No reference implementation exists on the machine this was written on: no rpm,
// no rpm2cpio, no rpmbuild. So the controls are of two kinds, and they are not of
// equal weight.
//
// REAL PACKAGES (testdata/rootfiles-el{5,7,9}-*.rpm). Three builds of the same
// source package, by rpmbuild, spanning 2007 to 2024 and the gzip, xz and zstd
// payload compressors. Their BYTES are rpmbuild's, which is what makes them worth
// having: the lead, both headers, the 8-byte padding, the index's byte order, the
// tag numbering and newc's 4-byte padding are all witnessed against output this
// package had no hand in. The EXPECTED VALUES were read out with an independent
// 40-line Python script written from the specification -- a weaker control than
// rpm itself, because two readers written from one specification can share a
// misreading of it. They are Public Domain and redistributable; see
// testdata/README.md.
//
// CRAFTED FIXTURES (build_test.go). A package this reader's own tests assemble.
// ⚠ A fixture of the writer's own making CANNOT FAIL THE WAY A REAL PACKAGE CAN:
// if the builder and the parser misunderstand the format the same way, the test
// agrees with the bug. The 8-byte padding is exactly that shape -- omit it in both
// and the round trip is perfect while every real package since 2000 fails.
//
// So the crafted fixtures are used only for what the real ones cannot provide,
// and each is a strictly weaker witness than a real package would be:
//
//   - a bzip2 payload, and an uncompressed one. rpm has supported both for
//     twenty years and neither appears in any mainstream distribution, so no
//     small public-domain package carries them. Go has no bzip2 WRITER either,
//     so the bzip2 archive was compressed by CPython's bz2 module from a cpio
//     that a third implementation wrote, and committed as a blob; the test
//     cross-checks that blob against build_test.go's builder so the two cannot
//     drift apart unnoticed.
//   - a package with NO PAYLOADCOMPRESSOR TAG, which rpm defines as gzip. Every
//     package older than rpm 4.0 (2000) is in this class and none was obtainable
//     small enough and clearly redistributable; the default is therefore reasoned
//     from rpm's source, not measured. THIS IS THE WEAKEST CLAIM IN THE PACKAGE.
//   - fifos, character and block devices, and sockets in a payload, which
//     exercise both directions of the st_mode translation. No rootfiles package
//     has one.
//   - every one of the ten index types in one header, and each corruption in
//     turn.
//
// # Reading the tests
//
// witness_test.go asserts BYTES per payload entry, never counts: a count is
// satisfied by the right number of wrong entries, and a mis-rounded newc pad
// produces exactly that. ablation_test.go removes one rule at a time and asserts
// the suite then fails; two of its six ablations have something to report, and
// README.md tabulates all of them.
package rpm
