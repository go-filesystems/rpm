// SPDX-License-Identifier: BSD-3-Clause

package rpm

import (
	"errors"
	"fmt"
	iofs "io/fs"
)

// ErrNotRPM is returned when the 96-byte lead does not begin with RPM's magic.
// It is the one error that means "this is not an RPM at all", which is what a
// format-probing caller such as go-filesystems/detect needs to tell apart from
// "this is an RPM and something in it is wrong".
var ErrNotRPM = errors.New("rpm: not an RPM package (bad lead magic)")

// ErrCorrupt is returned when the file IS an RPM -- the lead magic matched --
// and something inside it does not hold together: a header magic that is not
// there, a count or size that runs past the end of the file, an index entry
// whose offset points outside its own data store.
//
// ⛔ It is deliberately NOT wrapped in fs.ErrNotExist. A caller that maps a
// driver's errors onto HTTP or NFS status must be able to answer 500 for a
// damaged package and 404 for a name that is not in it; collapsing the two
// makes a corrupt package look like a routine miss and nothing anywhere
// reports the fault. See the error-contract note in
// github.com/go-filesystems/interface.
var ErrCorrupt = errors.New("rpm: corrupt package")

// ErrUnsupported is returned for a package this reader understands well enough
// to identify and not well enough to open: a payload format that is not cpio,
// or a compressor that is not one of the five named in PAYLOADCOMPRESSOR.
var ErrUnsupported = errors.New("rpm: unsupported")

// ErrNotFound is the driver's single "that path is not in this package"
// sentinel, and it satisfies the interface module's error contract:
// errors.Is(err, fs.ErrNotExist) is true for it and for anything wrapping it.
//
// Every site that raises it means a name that the payload does not carry. A
// payload that cannot be parsed raises ErrCorrupt instead, so the two do not
// share a sentinel and a broken package never reads as a 404 -- which is the
// distinction the interface module asks each driver to check before wrapping.
var ErrNotFound = fmt.Errorf("rpm: path not found in payload: %w", iofs.ErrNotExist)

// ErrNotRegular is returned by OpenFile and ReadFile for a path that is in the
// payload and is not a regular file -- a directory, a symlink, a device node.
// It satisfies fs.ErrInvalid rather than fs.ErrNotExist: the name resolved, so
// answering 404 would be wrong.
var ErrNotRegular = fmt.Errorf("rpm: not a regular file: %w", iofs.ErrInvalid)

// ErrReadOnly is returned by every mutating method. An RPM package is a
// distribution artefact: its payload is a single compressed stream and its
// headers carry digests over the bytes that follow them, so there is no
// in-place write that would leave a valid package behind.
var ErrReadOnly = errors.New("rpm: package is read-only")
