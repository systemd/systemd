---
title: systemd Coredump Handling
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# systemd Coredump Handling

## Support in the Service Manager (PID 1)

The systemd service manager natively provides coredump handling functionality,
as implemented by the Linux kernel.
Specifically, PID 1 provides the following functionality:

1. During very early boot it will raise the
   [`LIMIT_CORE`](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
   resource limit for itself to infinity (and thus implicitly also all its children).
   This removes any limits on the size of generated coredumps,
   for all invoked processes, from earliest boot on.
   (The Linux kernel sets the limit to 0 by default.)

2. At the same time it will turn off coredump handling in the kernel by writing
   `|/bin/false` into `/proc/sys/kernel/core_pattern` (also known as the
   "`kernel.core_pattern` sysctl"; see
   [core(5)](https://man7.org/linux/man-pages/man5/core.5.html) for
   details).
   This means that coredumps are not actually processed.
   (The Linux kernel sets the pattern to `core` by default, so that coredumps are written
   to the current working directory of the crashing process.)

Net effect: after PID1 has started and performed this setup coredumps are
disabled, but by means of the `kernel.core_pattern` sysctl rather than by
size limit.
This is generally preferable, since the pattern can be updated trivially at the right time to enable coredumping once the system is ready, taking comprehensive effect on all userspace.
(Or to say this differently: disabling coredumps via the size limit is problematic, since it cannot easily
be undone without iterating through all already running processes once the system is ready for coredump handling.)

Processing of core dumps may be enabled at the appropriate time by updating the
`kernel.core_pattern` sysctl.
Only coredumps that happen later will be processed.

During the final shutdown phase the `kernel.core_pattern` sysctl is updated
again to `|/bin/false`, disabling coredump support again, should it have been
enabled in the meantime.

This means coredump handling is generally not available during earliest boot
and latest shutdown, reflecting the fact that storage is typically not
available in these environments, and many other facilities are missing too that
are required to collect and process a coredump successfully.

## `systemd-coredump` Handler

The systemd suite provides a coredump handler
[`systemd-coredump`](https://www.freedesktop.org/software/systemd/man/systemd-coredump.html)
which can be enabled at build-time. It is activated during boot via the
`/usr/lib/sysctl.d/50-coredump.conf` drop-in file for
`systemd-sysctl.service`. It registers the `systemd-coredump` tool as
`kernel.core_pattern` sysctl.

`systemd-coredump` is implemented as socket activated service: when the kernel
invokes the userspace coredump handler, the received coredump file descriptor
is immediately handed off to the socket activated service
`systemd-coredump@.service` via the `systemd-coredump.socket` socket unit. This
means the coredump handler runs for a very short time only, and the potentially
*heavy* and security sensitive coredump processing work is done as part of the
specified service unit, and thus can take benefit of regular service resource
management and sandboxing.

The `systemd-coredump` handler will extract a backtrace and
[ELF packaging metadata](/PACKAGE_METADATA_FOR_EXECUTABLE_FILES)
from any coredumps it receives and log both.
The information about coredumps stored in the journal can be enumerated and queried with the
[`coredumpctl`](https://www.freedesktop.org/software/systemd/man/coredumpctl.html)
tool, for example for directly invoking a debugger such as `gdb` on a collected
coredump.

The handler writes coredump files to `/var/lib/systemd/coredump/`.
Old files are cleaned up periodically by
[`systemd-tmpfiles(8)`](https://www.freedesktop.org/software/systemd/man/systemd-tmpfiles.html).

## User Experience

With the above, any coredumps generated on the system are by default collected
and turned into logged events — except during very early boot and late
shutdown.
Individual services, processes or users can opt-out of coredump collection,
by setting `LIMIT_CORE` to 0 (or alternatively invoke
[`PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/prctl.2.html)).
The resource limit can be set freely by daemons/processes/users to arbitrary
values, which the coredump handler will respect.
The `coredumpctl` tool may be used to further analyze/debug coredumps.

## Alternative Coredump Handlers

While we recommend usage of the `systemd-coredump` handler, it's fully
supported to use alternative coredump handlers instead.
A similar implementation pattern is recommended.
Specifically:

1. Use a `sysctl.d/` drop-in to register your handler with the kernel.
   Make sure to include the `%c` specifier in the pattern (which reflects the
   crashing process' `RLIMIT_CORE`) and act on it:
   limit the stored coredump file to the specified limit.

2. Do not do heavy processing directly in the coredump handler.
   Instead, quickly pass off the kernel's coredump file descriptor to an
   auxiliary service running as service under the service manager,
   so that it can be done under supervision, sandboxing and resource management.

Note that at any given time only a single handler can be enabled, i.e. the
`kernel.core_pattern` sysctl cannot reference multiple executables.

## Packaging

It might make sense to split `systemd-coredump` into a separate distribution
package.
If doing so, make sure that `/usr/lib/sysctl.d/50-coredump.conf` and
the associated service and socket units are also added to the split off package.

Note that in a scenario where `systemd-coredump` is split out and not
installed, coredumping is turned off during the entire runtime of the system —
unless an alternative handler is installed, or behaviour is manually reverted
to legacy style handling (see below).

## Restoring Legacy Coredump Handling

The default policy of the kernel to write coredumps into the current working
directory of the crashing process is considered highly problematic by many,
including by the systemd maintainers.
Nonetheless, if users locally want to return to this behaviour, two changes must be made (followed by a reboot):

```console
$ mkdir -p /etc/sysctl.d
$ cat >/etc/sysctl.d/50-coredump.conf <<EOF
# Party like it's 1995!
kernel.core_pattern=core
EOF
```

and

```console
$ mkdir -p /etc/systemd/system.conf.d
$ cat >/etc/systemd/system.conf.d/50-coredump.conf <<EOF
[Manager]
DefaultLimitCORE=0:infinity
EOF
```
