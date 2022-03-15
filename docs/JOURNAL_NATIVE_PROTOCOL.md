---
title: Native Journal Protocol
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Native Journal Protocol

`systemd-journald.service` accepts log data via various protocols:

* Classic RFC3164 BSD syslog via the `/dev/log` socket
* STDOUT/STDERR of programs via `StandardOutput=journal` + `StandardError=journal` in service files (both of which are default settings)
* Kernel log messages via the `/dev/kmsg` device node
* Audit records via the kernel's audit subsystem
* Structured log messages via `journald`'s native protocol

The latter is what this document is about: if you are developing a program and
want to pass structured log data to `journald`, it's the Journal's native
protocol that you want to use. The systemd project provides the
[`sd_journal_print(3)`](https://www.freedesktop.org/software/systemd/man/sd_journal_print.html)
API that implements the client side of this protocol. This document explains
what this interface does behind the scenes, in case you'd like to implement a
client for it yourself, without linking to `libsystemd` — for example because
you work in a programming language other than C or otherwise want to avoid the
dependency.

## Basics

The native protocol of `journald` is spoken on the
`/run/systemd/journal/socket` `AF_UNIX`/`SOCK_DGRAM` socket on which
`systemd-journald.service` listens. Each datagram sent to this socket
encapsulates one journal entry that shall be written. Since datagrams are
subject to a size limit and we want to allow large journal entries, datagrams
sent over this socket may come in one of two formats:

* A datagram with the literal journal entry data as payload, without
  any file descriptors attached.

* A datagram with an empty payload, but with a single
  [`memfd`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
  file descriptor that contains the literal journal entry data.

Other combinations are not permitted, i.e. datagrams with both payload and file
descriptors, or datagrams with neither, or more than one file descriptor. Such
datagrams are ignored. The `memfd` file descriptor should be fully sealed. The
binary format in the datagram payload and in the `memfd` memory is
identical. Typically a client would attempt to first send the data as datagram
payload, but if this fails with an `EMSGSIZE` error it would immediately retry
via the `memfd` logic.

A client probably should bump up the `SO_SNDBUF` socket option of its `AF_UNIX`
socket towards `journald` in order to delay blocking I/O as much as possible.

## Data Format

Each datagram should consist of a number of environment-like key/value
assignments. Unlike environment variable assignments the value may contain NUL
bytes however, as well as any other binary data. Keys may not include the `=`
or newline characters (or any other control characters or non-ASCII characters)
and may not be empty.

Serialization into the datagram payload or `memfd` is straightforward: each
key/value pair is serialized via one of two methods:

* The first method inserts a `=` character between key and value, and suffixes
the result with `\n` (i.e. the newline character, ASCII code 10). Example: a
key `FOO` with a value `BAR` is serialized `F`, `O`, `O`, `=`, `B`, `A`, `R`,
`\n`.

* The second method should be used if the value of a field contains a `\n`
byte. In this case, the key name is serialized as is, followed by a `\n`
character, followed by a (non-aligned) little-endian unsigned 64bit integer
encoding the size of the value, followed by the literal value data, followed by
`\n`. Example: a key `FOO` with a value `BAR` may be serialized using this
second method as: `F`, `O`, `O`, `\n`, `\003`, `\000`, `\000`, `\000`, `\000`,
`\000`, `\000`, `\000`, `B`, `A`, `R`, `\n`.

If the value of a key/value pair contains a newline character (`\n`), it *must*
be serialized using the second method. If it does not, either method is
permitted. However, it is generally recommended to use the first method if
possible for all key/value pairs where applicable since the generated datagrams
are easily recognized and understood by the human eye this way, without any
manual binary decoding — which improves the debugging experience a lot, in
particular with tools such as `strace` that can show datagram content as text
dump. After all, log messages are highly relevant for debugging programs, hence
optimizing log traffic for readability without special tools is generally
desirable.

Note that keys that begin with `_` have special semantics in `journald`: they
are *trusted* and implicitly appended by `journald` on the receiving
side. Clients should not send them — if they do anyway, they will be ignored.

The most important key/value pair to send is `MESSAGE=`, as that contains the
actual log message text. Other relevant keys a client should send in most cases
are `PRIORITY=`, `CODE_FILE=`, `CODE_LINE=`, `CODE_FUNC=`, `ERRNO=`. It's
recommended to generate these fields implicitly on the client side. For further
information see the [relevant documentation of these
fields](https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html).

The order in which the fields are serialized within one datagram is undefined
and may be freely chosen by the client. The server side might or might not
retain or reorder it when writing it to the Journal.

Some programs might generate multi-line log messages (e.g. a stack unwinder
generating log output about a stack trace, with one line for each stack
frame). It's highly recommended to send these as a single datagram, using a
single `MESSAGE=` field with embedded newline characters between the lines (the
second serialization method described above must hence be used for this
field). If possible do not split up individual events into multiple Journal
events that might then be processed and written into the Journal as separate
entries. The Journal toolchain is capable of handling multi-line log entries
just fine, and it's generally preferred to have a single set of metadata fields
associated with each multi-line message.

Note that the same keys may be used multiple times within the same datagram,
with different values. The Journal supports this and will write such entries to
disk without complaining. This is useful for associating a single log entry
with multiple suitable objects of the same type at once. This should only be
used for specific Journal fields however, where this is expected. Do not use
this for Journal fields where this is not expected and where code reasonably
assumes per-event uniqueness of the keys. In most cases code that consumes and
displays log entries is likely to ignore such non-unique fields or only
consider the first of the specified values. Specifically, if a Journal entry
contains multiple `MESSAGE=` fields, likely only the first one is
displayed. Note that a well-written logging client library thus will not use a
plain dictionary for accepting structured log metadata, but rather a data
structure that allows non-unique keys, for example an array, or a dictionary
that optionally maps to a set of values instead of a single value.

## Example Datagram

Here's an encoded message, with various common fields, all encoded according to
the first serialization method, with the exception of one, where the value
contains a newline character, and thus the second method is needed to be used.

```
PRIORITY=3\n
SYSLOG_FACILITY=3\n
CODE_FILE=src/foobar.c\n
CODE_LINE=77\n
BINARY_BLOB\n
\004\000\000\000\000\000\000\000xx\nx\n
CODE_FUNC=some_func\n
SYSLOG_IDENTIFIER=footool\n
MESSAGE=Something happened.\n
```

(Lines are broken here after each `\n` to make things more readable. C-style
backslash escaping is used.)

## Automatic Protocol Upgrading

It might be wise to automatically upgrade to logging via the Journal's native
protocol in clients that previously used the BSD syslog protocol. Behaviour in
this case should be pretty obvious: try connecting a socket to
`/run/systemd/journal/socket` first (on success use the native Journal
protocol), and if that fails fall back to `/dev/log` (and use the BSD syslog
protocol).

Programs normally logging to STDERR might also choose to upgrade to native
Journal logging in case they are invoked via systemd's service logic, where
STDOUT and STDERR are going to the Journal anyway. By preferring the native
protocol over STDERR-based logging, structured metadata can be passed along,
including priority information and more — which is not available on STDERR
based logging. If a program wants to detect automatically whether its STDERR is
connected to the Journal's stream transport, look for the `$JOURNAL_STREAM`
environment variable. The systemd service logic sets this variable to a
colon-separated pair of device and inode number (formatted in decimal ASCII) of
the STDERR file descriptor. If the `.st_dev` and `.st_ino` fields of the
`struct stat` data returned by `fstat(STDERR_FILENO, …)` match these values a
program can be sure its STDERR is connected to the Journal, and may then opt to
upgrade to the native Journal protocol via an `AF_UNIX` socket of its own, and
cease to use STDERR.

Why bother with this environment variable check? A service program invoked by
systemd might employ shell-style I/O redirection on invoked subprograms, and
those should likely not upgrade to the native Journal protocol, but instead
continue to use the redirected file descriptors passed to them. Thus, by
comparing the device and inode number of the actual STDERR file descriptor with
the one the service manager passed, one can make sure that no I/O redirection
took place for the current program.

## Alternative Implementations

If you are looking for alternative implementations of this protocol (besides
systemd's own in `sd_journal_print()`), consider
[GLib's](https://gitlab.gnome.org/GNOME/glib/-/blob/main/glib/gmessages.c) or
[`dbus-broker`'s](https://github.com/bus1/dbus-broker/blob/main/src/util/log.c).

And that's already all there is to it.
