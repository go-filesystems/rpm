# testdata provenance

## The three real packages

Three builds of the **same source package**, `rootfiles`, by `rpmbuild`,
downloaded from public mirrors on 2026-09-26:

| file | upstream URL | `License` tag | size |
|---|---|---|---|
| `rootfiles-el5-gzip.rpm` | `https://vault.centos.org/5.11/os/x86_64/CentOS/rootfiles-8.1-1.1.1.noarch.rpm` | `Public Domain` | 4 686 B |
| `rootfiles-el7-xz.rpm` | `https://vault.centos.org/7.9.2009/os/x86_64/Packages/rootfiles-8.1-11.el7.noarch.rpm` | `Public Domain` | 7 512 B |
| `rootfiles-el9-zstd.rpm` | `https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/r/rootfiles-8.1-35.el9.noarch.rpm` | `Public Domain` | 9 556 B |

They are committed **unmodified**, byte for byte as the mirrors served them.

### Why these, and why it is safe to redistribute them

Each package's own `License` tag (RPM tag 1014) reads **`Public Domain`**, so
there is no copyright restriction on redistributing the packaged content and no
attribution obligation to carry. The content itself is five shell start-up files
(`.bashrc`, `.bash_profile`, `.bash_logout`, `.cshrc`, `.tcshrc`) totalling under
a kilobyte, plus a `tmpfiles.d` snippet in the el9 build — no compiled code, no
vendor branding, no trademarks in the payload.

Candidates under MIT and other permissive licences were available and were
**not** taken: MIT requires the notice to travel with the copy, and "public
domain, no obligation" leaves nothing to get wrong.

### Why three, rather than one small one

Because one of them cannot see the format's most error-prone rule.

The signature header's data store is padded to an 8-byte boundary before the
header proper begins. The el5 package's signature data ends at byte **440**,
which is already a multiple of 8, so for that package the padding is **zero
bytes wide** and a reader that omits the rule entirely opens it perfectly. The
el7 and el9 packages each need 4 bytes and each fail without it.

A witness set of one pre-2000 package would therefore have shipped the bug. See
the ablation table in `../README.md`.

The three also span the three payload compressors that exist in the wild —
gzip (2007), xz (2020), zstd (2024) — which is what makes the compressor
dispatch measurable against real output rather than against fixtures.

### How the expected values were established

No reference implementation was available: `rpm`, `rpm2cpio` and `rpmbuild` are
all absent from the machine this was written on. The expected values in
`witness_test.go` — names, versions, summaries, payload offsets, per-file bytes
— were read out with an independent ~40-line Python script written from the
format specification, using `gzip`, `lzma` and the `zstd` CLI.

⚠ **That is weaker than `rpm` itself would be.** Two readers written from one
specification can share a misreading of it. What the fixtures do establish
firmly is that the **bytes** came from `rpmbuild`: the layout is not this
package's invention, only its interpretation is doubled rather than
cross-checked.

## `crafted-payload.cpio.bz2`

A hand-built newc cpio archive, bzip2-compressed. 272 bytes.

It exists because **no mainstream distribution ships a bzip2 payload** — rpm has
supported it for twenty years and nothing uses it — and because **Go has no
bzip2 writer** in its standard library, so the test suite cannot produce one at
run time.

It was produced by this script, which is a third independent implementation of
newc's layout (the shipping reader is the first, `build_test.go`'s `buildCpio`
the second):

```python
import bz2
recs = [("./etc", 0o040755, b"", 1),
        ("./etc/demo.conf", 0o100644, b"key = value\n", 2),
        ("./etc/link", 0o120777, b"demo.conf", 3),
        ("./usr/share/deep/nested.txt", 0o100600, b"deep\n", 4),
        ("./dev/fifo", 0o010644, b"", 5),
        ("./dev/chr", 0o020666, b"", 6),
        ("./dev/blk", 0o060660, b"", 7),
        ("./run/sock", 0o140777, b"", 8),
        ("TRAILER!!!", 0, b"", 0)]
out = bytearray()
for name, mode, data, ino in recs:
    nb = name.encode() + b"\0"
    f = [ino, mode, 0, 0, 1, 0x5F000000, len(data), 0, 0, 0, 0, len(nb), 0]
    out += b"070701" + "".join("%08X" % v for v in f).encode() + nb
    while len(out) % 4: out += b"\0"
    out += data
    while len(out) % 4: out += b"\0"
open("crafted-payload.cpio.bz2", "wb").write(bz2.compress(bytes(out), 9))
```

`TestBzip2Payload` decompresses the blob and asserts it equals
`buildCpio(demoRecs()...)` byte for byte, so the committed blob and the Go
builder cannot drift apart unnoticed.

⚠ Three implementations that agree are still three implementations written from
one specification. The real packages above are the evidence; this is the only way
to reach the bzip2 branch at all.

## Everything here is embedded

The emulated CI lanes copy a `go test -c` binary into a QEMU container with **no
repository beside it**, so a runtime `os.ReadFile("testdata/...")` would pass on
four native lanes and fail on four emulated ones. Every *fixture* in this directory is
pulled in with `//go:embed` (see `witness_test.go`). Verify with:

```
go test -c -o /tmp/t.test . && cd /tmp && ./t.test
```
