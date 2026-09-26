<p align="center"><img src="https://raw.githubusercontent.com/go-filesystems/brand/main/social/go-filesystems-rpm.png" alt="go-filesystems/rpm" width="720"></p>

# go-filesystems/rpm

A pure-Go, CGO-free reader for **RPM packages**: the metadata, and the cpio
payload as a `filesystem.Filesystem`.

No rpm library, no `librpm`, no shelling out. Works on every platform Go targets.

```go
import (
    "os"

    "github.com/go-filesystems/rpm"
)

f, _ := os.Open("rootfiles-8.1-35.el9.noarch.rpm")
st, _ := f.Stat()

// Headers only: a few kilobytes, whatever the package weighs.
p, err := rpm.Metadata(f, st.Size())
// p.Name, p.Version, p.Release, p.Arch, p.Summary, p.License,
// p.PayloadFormat, p.PayloadCompressor, p.NEVRA()

// Headers and payload, as a filesystem.
fsys, err := rpm.OpenReader(f, st.Size())
body, err := fsys.ReadFile("usr/share/rootfiles/.bashrc")
```

## API

```go
func Metadata(r io.ReaderAt, size int64) (*Package, error)
func Open(r io.ReaderAt, size int64) (*FS, error)
func OpenReader(r io.ReaderAt, size int64) (filesystem.Filesystem, error)
```

`filesystem` is [`github.com/go-filesystems/interface`](https://github.com/go-filesystems/interface)
v0.3.0. `*FS` satisfies `filesystem.Filesystem` and the optional
`filesystem.Opener`; `FS.OpenFile` returns a `filesystem.File` whose `ReadAt`
follows `io.ReaderAt` to the letter.

Every mutating method (`WriteFile`, `MkDir`, `DeleteFile`, `DeleteDir`,
`Rename`) returns `ErrReadOnly`. An RPM's headers carry digests over the bytes
that follow them and its payload is one compressed stream, so there is no
in-place write that leaves a valid package behind.

`Header` is exposed for tags this package does not name: `h.String(tag)`,
`h.Strings(tag)`, `h.Int(tag)`, `h.Ints(tag)`, `h.Bytes(tag)`, `h.Has(tag)`,
`h.Lookup(tag)`.

### Errors

| sentinel | meaning |
|---|---|
| `ErrNotRPM` | the lead magic is not `ED AB EE DB` — this is not an RPM |
| `ErrCorrupt` | it *is* an RPM and something inside it does not hold together |
| `ErrUnsupported` | a payload format that is not cpio, or a compressor that is not one of the five |
| `ErrNotFound` | a path the payload does not carry — satisfies `fs.ErrNotExist` |
| `ErrNotRegular` | the path resolved and is the wrong kind — satisfies `fs.ErrInvalid` |
| `ErrReadOnly` | every mutating method |

⛔ `ErrCorrupt` is deliberately **not** wrapped in `fs.ErrNotExist`. A caller
mapping this onto HTTP or NFS must be able to answer 500 for a damaged package
and 404 for a name that is not in it; collapsing the two makes a real fault
arrive as a routine miss and nothing anywhere reports it. Both directions are
asserted in `witness_test.go`.

## Memory

`Metadata` reads the two headers and nothing else.

⛔ `Open` decompresses the **whole payload into memory**, and that is the
format rather than a shortcut: an RPM payload is *one* compressed stream, so the
last file's bytes cannot be reached without decoding every byte before them.
Budget for the **installed** size of the package, not its download size. It is
also what makes `filesystem.Opener` honest here — the bytes are already
resident, so a range read costs a copy, and the decoding is accounted for once
at open instead of hidden inside each read.

## The cpio reader comes from `go-filesystems/cpio`

The payload is a cpio archive and [`go-filesystems/cpio`](https://github.com/go-filesystems/cpio)
parses it. This package used to carry a **second copy** of that parser — newc only,
about 220 lines — with a notice here saying so and asking for exactly this
consolidation. The cost it named was real: *a defect fixed in one copy stayed present
in the other.*

What stays here is the mapping onto this package's `entry`, the index in `fs.go`, and
`posixMode`, which is the direction the shared parser does not go. **The filesystem is
deliberately not shared:** a payload is one compressed stream, so it is in memory and
entries are sections of it, while `unarchive` indexes into a file it keeps open.

It calls `cpio.RecordsExact`, not `cpio.Records`. A payload's length is known exactly,
so a record that does not parse, a magic that is not one, and a missing trailer are all
**damage** — not the block padding an initramfs legitimately carries. `Records`
tolerates all three, and using it here turned three of this package's refusals into
silent successes, which is how that distinction was found.

### Two disagreements the consolidation settled

Neither was visible to any test on either side, because each repository only ever ran
its own reader.

- **Every numeric header field is checked.** This package did; the other ignored the
  errors on inode and mtime, so a header with a non-hex inode parsed to `inode 0` and
  looked perfectly ordinary.
- **The inode is carried**, because this package reports it in `Stat`. It is **not**
  portable across cpio variants: odc's field and the old binary variant's are too
  narrow to hold a real one, and `cpio(1)` renumbers them 1..n.

## ⚠⚠ Where the witnesses come from, and what that costs in confidence

**No reference implementation was available.** `rpm`, `rpm2cpio` and `rpmbuild`
are all absent from the machine this was written on. So there are two kinds of
control here and they are not of equal weight.

### Real packages — the load-bearing witnesses

`testdata/` holds three builds of the same source package by **rpmbuild**,
spanning 2007 to 2024 and three payload compressors:

| fixture | built | compressor | sig. padding | bytes |
|---|---|---|---|---|
| `rootfiles-el5-gzip.rpm` | CentOS 5 (2007) | gzip | **0** | 4 686 |
| `rootfiles-el7-xz.rpm` | CentOS 7 (2020) | xz | 4 | 7 512 |
| `rootfiles-el9-zstd.rpm` | Rocky 9 (2024) | zstd | 4 | 9 556 |

All three are `License: Public Domain` — see `testdata/README.md` for the
provenance and the redistribution reasoning. Their payloads carry five real
regular files with real bytes, and the tests assert **bytes**, never counts: a
count is satisfied by the right number of wrong entries, which is exactly what a
mis-rounded newc pad produces.

What they witness, because the bytes are rpmbuild's and this package had no hand
in them: the lead, both header structures, the 8-byte padding, the index's byte
order, the tag numbering, the gzip/xz/zstd dispatch, and newc's 4-byte padding.

The **expected values** were read out with an independent 40-line Python script
written from the specification. That is weaker than `rpm` would be: two readers
written from one specification can share a misreading of it. The *bytes* are
still rpmbuild's; only the *interpretation* is doubled rather than
cross-checked.

### Crafted fixtures — strictly weaker, and used only where nothing else exists

⚠ **A fixture of the writer's own making cannot fail the way a real package
can.** If the builder and the parser misunderstand the format in the same way,
the test agrees with the bug. The 8-byte padding is exactly that shape: omit it
in both and the round trip is perfect, while every real package since 2000
fails.

So `build_test.go` is used only for what the real packages cannot provide:

- **a bzip2 payload, and an uncompressed one.** rpm has supported both for
  twenty years; neither appears in any mainstream distribution, so no small
  public-domain package carries them. Go has no bzip2 *writer* either, so the
  bzip2 archive was compressed by CPython's `bz2` from a cpio that a *third*
  implementation wrote, and committed as `testdata/crafted-payload.cpio.bz2`.
  The test cross-checks that blob against the Go builder byte for byte, so the
  two cannot drift apart unnoticed.
- **a package with no `PAYLOADCOMPRESSOR` tag**, which rpm defines as gzip.
  Every package older than rpm 4.0 (2000) is in this class and none was
  obtainable small enough and clearly redistributable. The default is reasoned
  from rpm's source, not measured. **This is the weakest claim in the package.**
- **fifos, character and block devices, sockets** in a payload, which exercise
  both directions of the `st_mode` translation. No `rootfiles` package has one.
- every one of the ten index types in one header, and each corruption in turn.

## The ablation table

Each ablation removes one rule and asserts the suite then **fails on a real
package**. A rule nothing depends on passes its test *and* passes with the rule
deleted, which is indistinguishable from a rule that matters — so the ablation
is the measurement, not the test.

`TestAblationHarnessMatchesTheReader` is the control: the parametrised harness
with every knob at its correct setting must reproduce `Metadata` exactly, on all
three real packages. Without it the rest measures a copy.

| # | rule removed | result | note |
|---|---|---|---|
| 1 | the 8-byte padding after the signature header | **fails on 2 of 3** | ⛔ **PASSES on el5**: its signature data ends at byte 440, already 8-aligned, so the padding is zero bytes wide and the rule is invisible to it. A reader tested against one pre-2000 package would ship the bug. This is why the witness set spans three build eras. |
| 2 | big-endian index fields (read little-endian) | fails on 3 of 3 | ⛔ **and it produces no parse error.** Tag 1000 read backwards is `0xE8030000`, so every lookup *misses* and the package comes back with an empty name — "missing metadata", not a byte-order fault. Asserting on the error would have found nothing; the test asserts on the **values**. |
| 3 | the lead's 96-byte length (tried 64, 95, 97, 128) | fails on 3 of 3 | every offset refused at the signature magic |
| 4 | the payload compressor dispatch (each payload read as each other compressor) | fails on 3 of 3 | ⚠ **`none` decompresses "successfully"** — it hands the bytes through untouched — and is then refused one layer later, at the cpio magic. That is the case `readCpioRecord`'s error message names explicitly, because it is where a missing `PAYLOADCOMPRESSOR` tag surfaces. |
| 5 | each tag lookup (`NAME`, `VERSION`, `RELEASE`, `ARCH`, `SUMMARY`, `PAYLOADFORMAT`), renumbered in the real file | fails on 3 of 3 × 6 | the *file* is mutated, not the reader, so this exercises the shipping lookup. Each renumbering empties exactly one field and moves nothing else. `PAYLOADCOMPRESSOR` is its own case: removed, it must give **gzip**, not `""` — and the package must then fail to open, because it really is zstd. |
| 6 | newc's 4-byte padding (rounded to 1) | fails on 3 of 3 | 1 record read instead of 5, 5 and 7 |

Two findings, both recorded above: **ablation 1 passes on one of the three
witnesses**, and **ablation 2 fails silently rather than loudly**.

## A further measurement: the lead cannot be trusted

`TestLeadDisagreesWithHeader` records it. All three packages are `noarch` by
their `ARCH` tag; their *lead* `Archnum` fields say 255, 1 and 255. A caller
that decided the architecture from the lead would get a different answer per
build era for the same package. `Metadata` takes every fact from the main header
and exposes `Lead` only so a tool can show what the lead claims.

## Development

```
export GOWORK=off GOFLAGS=-mod=mod
go vet ./...
go test -race ./...
```

CI runs 4 native lanes (linux/amd64, linux/arm64, darwin/arm64, windows/amd64)
and 4 emulated ones (riscv64, loong64, ppc64le, s390x) behind a **100%
statement coverage gate**.

⚠ The emulated lanes copy a `go test -c` binary into a QEMU container with **no
`testdata/` beside it**, so every fixture is embedded with `//go:embed`. Verify
that yourself with:

```
go test -c -o /tmp/t.test . && cd /tmp && ./t.test
```
