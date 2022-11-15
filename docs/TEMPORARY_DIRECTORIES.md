---
title: Using /tmp/ and /var/tmp/ Safely
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Using `/tmp/` and `/var/tmp/` Safely

`/tmp/` and `/var/tmp/` are two world-writable directories Linux systems
provide for temporary files. The former is typically on `tmpfs` and thus
backed by RAM/swap, and flushed out on each reboot. The latter is typically a
proper, persistent file system, and thus backed by physical storage. This
means:

1. `/tmp/` should be used for smaller, size-bounded files only; `/var/tmp/`
   should be used for everything else.

2. Data that shall survive a boot cycle shouldn't be placed in `/tmp/`.

If the `$TMPDIR` environment variable is set, use that path, and neither use
`/tmp/` nor `/var/tmp/` directly.

See
[file-hierarchy(7)](https://www.freedesktop.org/software/systemd/man/file-hierarchy.html)
for details about these two (and most other) directories of a Linux system.

## Common Namespace

Note that `/tmp/` and `/var/tmp/` each define a common namespace shared by all
local software. This means guessable file or directory names below either
directory directly translate into a 🚨 Denial-of-Service (DoS) 🚨 vulnerability
or worse: if some software creates a file or directory `/tmp/foo` then any
other software that wants to create the same file or directory `/tmp/foo`
either will fail (as the file already exists) or might be tricked into using
untrusted files. Hence: do not use guessable names in `/tmp/` or `/var/tmp/` —
if you do you open yourself up to a local DoS exploit or worse. (You can get
away with using guessable names, if you pre-create subdirectories below `/tmp/`
for them, like X11 does with `/tmp/.X11-unix/` through `tmpfiles.d/`
drop-ins. However this is not recommended, as it is fully safe only if these
directories are pre-created during early boot, and thus problematic if package
installation during runtime is permitted.)

To protect yourself against these kinds of attacks Linux provides a couple of
APIs that help you avoiding guessable names. Specifically:

1. Use [`mkstemp()`](https://man7.org/linux/man-pages/man3/mkstemp.3.html)
   (POSIX), `mkostemp()` (glibc),
   [`mkdtemp()`](https://man7.org/linux/man-pages/man3/mkdtemp.3.html) (POSIX),
   [`tmpfile()`](https://man7.org/linux/man-pages/man3/tmpfile.3.html) (C89)

2. Use [`open()`](https://man7.org/linux/man-pages/man2/open.2.html) with
   `O_TMPFILE` (Linux)

3. [`memfd_create()`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
   (Linux; this doesn't bother with `/tmp/` or `/var/tmp/` at all, but uses the
   same RAM/swap backing as `tmpfs` uses, hence is very similar to `/tmp/`
   semantics.)

For system services systemd provides the `PrivateTmp=` boolean setting. If
turned on for a service (👍 which is highly recommended), `/tmp/` and
`/var/tmp/` are replaced by private sub-directories, implemented through Linux
file system namespacing and bind mounts. This means from the service's point of
view `/tmp/` and `/var/tmp/` look and behave like they normally do, but in
reality they are private sub-directories of the host's real `/tmp/` and
`/var/tmp/`, and thus not system-wide locations anymore, but service-specific
ones. This reduces the surface for local DoS attacks substantially. While it is
recommended to turn this option on, it's highly recommended for applications
not to rely on this solely to avoid DoS vulnerabilities, because this option is
not available in environments where file system namespaces are prohibited, for
example in certain container environments. This option is hence an extra line
of defense, but should not be used as an excuse to rely on guessable names in
`/tmp/` and `/var/tmp/`. When this option is used, the per-service temporary
directories are removed whenever the service shuts down, hence the lifecycle of
temporary files stored in it is substantially different from the case where
this option is not used. Also note that some applications use `/tmp/` and
`/var/tmp/` for sharing files and directories. If this option is turned on this
is not possible anymore as after all each service gets its own instances of
both directories.

## Automatic Clean-Up

By default, `systemd-tmpfiles` will apply a concept of ⚠️ "ageing" to all files
and directories stored in `/tmp/` and `/var/tmp/`. This means that files that
have neither been changed nor read within a specific time frame are
automatically removed in regular intervals. (This concept is not new to
`systemd-tmpfiles` btw, it's inherited from previous subsystems such as
`tmpwatch`.) By default files in `/tmp/` are cleaned up after 10 days, and
those in `/var/tmp` after 30 days.

This automatic clean-up is important to ensure disk usage of these temporary
directories doesn't grow without bounds, even when programs abort unexpectedly
or otherwise don't clean up the temporary files/directories they create. On the
other hand it creates problems for long-running software that does not expect
temporary files it operates on to be suddenly removed. There are a couple of
strategies to avoid these issues:

1. Make sure to always keep a file descriptor to the temporary files you
   operate on open, and only access the files through them. This way it doesn't
   matter whether the files have been unlinked from the file system: as long as
   you have the file descriptor open you can still access the file for both
   reading and writing. When operating this way it is recommended to delete the
   files right after creating them to ensure that on unexpected program
   termination the files or directories are implicitly released by the kernel.

2. 🥇 Use `memfd_create()` or `O_TMPFILE`. This is an extension of the
   suggestion above: files created this way are never linked under a filename
   in the file system. This means they are not subject to ageing (as they come
   unlinked out of the box), and there's no time window where a directory entry
   for the file exists in the file system, and thus behaviour is fully robust
   towards unexpected program termination as there are never files on disk that
   need to be explicitly deleted.

3. 🥇 Operate below a sub-directory of `/tmp/` and `/var/tmp/` you created, and
   take a BSD file lock ([`flock(dir_fd,
   LOCK_SH)`](https://man7.org/linux/man-pages/man2/flock.2.html)) on that
   sub-directory. This is particularly interesting when operating on more than
   a single file, or on file nodes that are not plain regular files, for
   example when extracting a tarball to a temporary directory. The ageing
   algorithm will skip all directories (and everything below them) that are
   locked through a BSD file lock. As BSD file locks are automatically released
   when the file descriptor they are taken on is closed, and all file
   descriptors opened by a process are implicitly closed when it exits, this is
   a robust mechanism that ensures all temporary files are subject to ageing
   when the program that owns them dies, but not while it is still running. Use
   this when decompressing tarballs that contain files with old
   modification/access times, as extracted files are otherwise immediately
   candidates for deletion by the ageing algorithm. The
   [`flock`](https://man7.org/linux/man-pages/man1/flock.1.html) tool of the
   `util-linux` packages makes this concept available to shell scripts. Note
   that `systemd-tmpfiles` only checks for BSD file locks on directories, locks
   on other types of file nodes (including regular files) are not considered.

4. Keep the access time of all temporary files created current. In regular
   intervals, use `utimensat()` or a related call to update the access time
   ("atime") of all files that shall be kept around. Since the ageing algorithm
   looks at the access time of files when deciding whether to delete them, it's
   sufficient to update their access times in sufficiently frequent intervals to
   ensure the files are not deleted. Since most applications (and tools such as
   `ls`) primarily care for the modification time (rather than the access time)
   using the access time for this purpose should be acceptable.

5. Set the "sticky" bit on regular files. The ageing logic skips deletion of
   all regular files that have the sticky bit (`chmod +t`) set. This is
   honoured for regular files only however, and has no effect on directories as
   the sticky bit has a different meaning for them.

6. Don't use `/tmp/` or `/var/tmp/`, but use your own sub-directory under
   `/run/` or `$XDG_RUNTIME_DIRECTORY` (the former if privileged, the latter if
   unprivileged), or `/var/lib/` and `~/.config/` (similar, but with
   persistency and suitable for larger data). The two temporary directories
   `/tmp/` and `/var/tmp/` come with the implicit clean-up semantics described
   above. When this is not desired, it's possible to create private per-package
   runtime or state directories, and place all temporary files there. However,
   do note that this means opting out of any kind of automatic clean-up, and it
   is hence particularly essential that the program cleans up generated files
   in these directories when they are no longer needed, in particular when the
   program dies unexpectedly. Note: this strategy is only really suitable for
   packages that operate in a "system wide singleton" fashion with "long"
   persistence of its data or state, i.e. as opposed to programs that run in
   multiple parallel or short-living instances. This is because a private
   directory under `/run` (and the other mentioned directories) is itself
   system and package specific singleton with greater longevity.

5. Exclude your temporary files from clean-ups via a `tmpfiles.d/` drop-in
   (which includes drop-ins in the runtime-only directory
   `/run/tmpfiles.d/`). The `x`/`X` line types may be used to exclude files
   matching the specified globbing patterns from the ageing logic. If this is
   used, automatic clean-up is not done for matching files and directory, and
   much like with the previous option it's hence essential that the program
   generating these temporary files carefully removes the temporary files it
   creates again, and in particular so if it dies unexpectedly.

🥇 The semantics of options 2 (in case you only deal with temporary files, not
directories) and 3 (in case you deal with both) in the list above are in most
cases the most preferable. It is thus recommended to stick to these two
options.

While the ageing logic is very useful as a safety concept to ensure unused
files and directories are eventually removed a well written program avoids even
creating files that need such a clean-up. In particular:

1. Use `memfd_create()` or `O_TMPFILE` when creating temporary files.

2. `unlink()` temporary files right after creating them. This is very similar
   to `O_TMPFILE` behaviour: consider deleting temporary files right after
   creating them, while keeping open a file descriptor to them. Unlike
   `O_TMPFILE` this method also works on older Linux systems and other OSes
   that do not implement `O_TMPFILE`.

## Disk Quota

Generally, files allocated from `/tmp/` and `/var/tmp/` are allocated from a
pool shared by all local users. Moreover the space available in `/tmp/` is
generally more restricted than `/var/tmp/`. This means, that in particular in
`/tmp/` space should be considered scarce, and programs need to be prepared
that no space is available. Essential programs might require a fallback logic
using a different location for storing temporary files hence. Non-essential
programs at least need to be prepared for `ENOSPC` errors and generate useful,
actionable error messages.

Some setups employ per-user quota on `/var/tmp/` and possibly `/tmp/`, to make
`ENOSPC` situations less likely, and harder to trigger from unprivileged
users. However, in the general case no such per-user quota is implemented
though, in particular not when `tmpfs` is used as backing file system, because
— even today — `tmpfs` still provides no native quota support in the kernel.

## Early Boot Considerations

Both `/tmp/` and `/var/tmp/` are not necessarily available during early boot,
or — if they are available early — are not writable. This means software that
is intended to run during early boot (i.e. before `basic.target` — or more
specifically `local-fs.target` — is up) should not attempt to make use of
either. Interfaces such as `memfd_create()` or files below a package-specific
directory in `/run/` are much better options in this case. (Note that some
packages instead use `/dev/shm/` for temporary files during early boot; this is
not advisable however, as it offers no benefits over a private directory in
`/run/` as both are backed by the same concept: `tmpfs`. The directory
`/dev/shm/` exists to back POSIX shared memory (see
[`shm_open()`](https://man7.org/linux/man-pages/man3/shm_open.3.html) and
related calls), and not as a place for temporary files. `/dev/shm` is
problematic as it is world-writable and there's no automatic clean-up logic in
place.)
