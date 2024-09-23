---
title: File Descriptor Store
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# The File Descriptor Store

*TL;DR: The systemd service manager may optionally maintain a set of file
descriptors for each service. Those file descriptors are under control of the
service. Storing file descriptors in the manager makes is easier to restart
services without dropping connections or losing state.*

Since its inception `systemd` has supported the *socket* *activation*
mechanism: the service manager creates and listens on some sockets (and similar
UNIX file descriptors) on behalf of a service, and then passes them to the
service during activation of the service via UNIX file descriptor (short: *fd*)
passing over `execve()`. This is primarily exposed in the
[.socket](https://www.freedesktop.org/software/systemd/man/systemd.socket.html)
unit type.

The *file* *descriptor* *store* (short: *fdstore*) extends this concept, and
allows services to *upload* during runtime additional fds to the service
manager that it shall keep on its behalf. File descriptors are passed back to
the service on subsequent activations, the same way as any socket activation
fds are passed.

If a service fd is passed to the fdstore logic of the service manager it only
maintains a duplicate of it (in the sense of UNIX
[`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html)), the fd remains
also in possession of the service itself, and it may (and is expected to)
invoke any operations on it that it likes.

The primary use-case of this logic is to permit services to restart seamlessly
(for example to update them to a newer version), without losing execution
context, dropping pinned resources, terminating established connections or even
just momentarily losing connectivity. In fact, as the file descriptors can be
uploaded freely at any time during the service runtime, this can even be used
to implement services that robustly handle abnormal termination and can recover
from that without losing pinned resources.

Note that Linux supports the
[`memfd`](https://man7.org/linux/man-pages/man2/memfd_create.2.html) concept
that allows associating a memory-backed fd with arbitrary data. This may
conveniently be used to serialize service state into and then place in the
fdstore, in order to implement service restarts with full service state being
passed over.

## Basic Mechanism

The fdstore is enabled per-service via the
[`FileDescriptorStoreMax=`](https://www.freedesktop.org/software/systemd/man/systemd.service.html#FileDescriptorStoreMax=)
service setting. It defaults to zero (which means the fdstore logic is turned
off), but can take an unsigned integer value that controls how many fds to
permit the service to upload to the service manager to keep simultaneously.

If set to values > 0, the fdstore is enabled. When invoked the service may now
(asynchronously) upload file descriptors to the fdstore via the
[`sd_pid_notify_with_fds()`](https://www.freedesktop.org/software/systemd/man/sd_pid_notify_with_fds.html)
API call (or an equivalent re-implementation). When uploading the fds it is
necessary to set the `FDSTORE=1` field in the message, to indicate what the fd
is intended for. It's recommended to also set the `FDNAME=…` field to any
string of choice, which may be used to identify the fd later.

Whenever the service is restarted the fds in its fdstore will be passed to the
new instance following the same protocol as for socket activation fds. i.e. the
`$LISTEN_FDS`, `$LISTEN_PIDS`, `$LISTEN_FDNAMES` environment variables will be
set (the latter will be populated from the `FDNAME=…` field mentioned
above). See
[`sd_listen_fds()`](https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html)
for details on receiving such fds in a service. (Note that the name set in
`FDNAME=…` does not need to be unique, which is useful when operating with
multiple fully equivalent sockets or similar, for example for a service that
both operates on IPv4 and IPv6 and treats both more or less the same.).

And that's already the gist of it.

## Seamless Service Restarts

A system service that provides a client-facing interface that shall be able to
seamlessly restart can make use of this in a scheme like the following:
whenever a new connection comes in it uploads its fd immediately into its
fdstore. At appropriate times it also serializes its state into a memfd it
uploads to the service manager — either whenever the state changed
sufficiently, or simply right before it terminates. (The latter of course means
that state only survives on *clean* restarts and abnormal termination implies the
state is lost completely — while the former would mean there's a good chance the
next restart after an abnormal termination could continue where it left off
with only some context lost.)

Using the fdstore for such seamless service restarts is generally recommended
over implementations that attempt to leave a process from the old service
instance around until after the new instance already started, so that the old
then communicates with the new service instance, and passes the fds over
directly. Typically service restarts are a mechanism for implementing *code*
updates, hence leaving two version of the service running at the same time is
generally problematic. It also collides with the systemd service manager's
general principle of guaranteeing a pristine execution environment, a pristine
security context, and a pristine resource management context for freshly
started services, without uncontrolled "leftovers" from previous runs. For
example: leaving processes from previous runs generally negatively affects
lifecycle management (i.e. `KillMode=none` must be set), which disables large
parts of the service managers state tracking, resource management (as resource
counters cannot start at zero during service activation anymore, since the old
processes remaining skew them), security policies (as processes with possibly
out-of-date security policies – SElinux, AppArmor, any LSM, seccomp, BPF — in
effect remain), and similar.

## File Descriptor Store Lifecycle

By default any file descriptor stored in the fdstore for which a `POLLHUP` or
`POLLERR` is seen is automatically closed and removed from the fdstore. This
behavior can be turned off, by setting the `FDPOLL=0` field when uploading the
fd via `sd_notify_with_fds()`.

The fdstore is automatically closed whenever the service is fully deactivated
and no jobs are queued for it anymore. This means that a restart job for a
service will leave the fdstore intact, but a separate stop and start job for
it — executed synchronously one after the other — will likely not.

This behavior can be modified via the
[`FileDescriptorStorePreserve=`](https://www.freedesktop.org/software/systemd/man/systemd.service.html#FileDescriptorStorePreserve=)
setting in service unit files. If set to `yes` the fdstore will be kept as long
as the service definition is loaded into memory by the service manager, i.e. as
long as at least one other loaded unit has a reference to it.

The `systemctl clean --what=fdstore …` command may be used to explicitly clear
the fdstore of a service. This is only allowed when the service is fully
deactivated, and is hence primarily useful in case
`FileDescriptorStorePreserve=yes` is set (because the fdstore is otherwise
fully closed anyway in this state).

Individual file descriptors may be removed from the fdstore via the
`sd_notify()` mechanism, by sending an `FDSTOREREMOVE=1` message, accompanied
by an `FDNAME=…` string identifying the fds to remove. (The name does not have
to be unique, as mentioned, in which case *all* matching fds are
closed). Generally it's a good idea to send such messages to the service
manager during initialization of the service whenever an unrecognized fd is
received, to make the service robust for code updates: if an old version
uploaded an fd that the new version doesn't recognize anymore it's good idea to
close it both in the service and in the fdstore.

Note that storing a duplicate of an fd in the fdstore means the resource pinned
by the fd remains pinned even if the service closes its duplicate of the
fd. This in particular means that peers on a connection socket uploaded this
way will not receive an automatic `POLLHUP` event anymore if the service code
issues `close()` on the socket. It must accompany it with an `FDSTOREREMOVE=1`
notification to the service manager, so that the fd is comprehensively closed.

## Access Control

Access to the fds in the file descriptor store is generally restricted to the
service code itself. Pushing fds into or removing fds from the fdstore is
subject to the access control restrictions of any other `sd_notify()` message,
which is controlled via
[`NotifyAccess=`](https://www.freedesktop.org/software/systemd/man/systemd.service.html#NotifyAccess=).

By default only the main service process hence can push/remove fds, but by
setting `NotifyAccess=all` this may be relaxed to allow arbitrary service
child processes to do the same.

## Soft Reboot

The fdstore is particularly interesting in [soft
reboot](https://www.freedesktop.org/software/systemd/man/systemd-soft-reboot.service.html)
scenarios, as per `systemctl soft-reboot` (which restarts userspace like in a
real reboot, but leaves the kernel running). File descriptor stores that remain
loaded at the very end of the system cycle — just before the soft-reboot – are
passed over to the next system cycle, and propagated to services they originate
from there. This enables updating the full userspace of a system during
runtime, fully replacing all processes without losing pinning resources,
interrupting connectivity or established connections and similar.

This mechanism can be enabled either by making sure the service survives until
the very end (i.e. by setting `DefaultDependencies=no` so that it keeps running
for the whole system lifetime without being regularly deactivated at shutdown)
or by setting `FileDescriptorStorePreserve=yes` (and referencing the unit
continuously).

For further details see [Resource
Pass-Through](https://www.freedesktop.org/software/systemd/man/systemd-soft-reboot.service.html#Resource%20Pass-Through).

## Initrd Transitions

The fdstore may also be used to pass file descriptors for resources from the
initrd context to the main system. Restarting all processes after the
transition is important as code running in the initrd should generally not
continue to run after the switch to the host file system, since that pins
backing files from the initrd, and the initrd might contain different versions
of programs than the host.

Any service that still runs during the initrd→host transition will have its
fdstore passed over the transition, where it will be passed back to any queued
services of the same name.

The soft reboot cycle transition and the initrd→host transition are
semantically very similar, hence similar rules apply, and in both cases it is
recommended to use the fdstore if pinned resources shall be passed over.

## Debugging

The
[`systemd-analyze`](https://www.freedesktop.org/software/systemd/man/systemd-analyze.html#systemd-analyze%20fdstore%20%5BUNIT...%5D)
tool may be used to list the current contents of the fdstore of any running
service.

The
[`systemd-run`](https://www.freedesktop.org/software/systemd/man/systemd-run.html)
tool may be used to quickly start a testing binary or similar as a service. Use
`-p FileDescriptorStoreMax=4711` to enable the fdstore from `systemd-run`'s
command line. By using the `-t` switch you can even interactively communicate
via processes spawned that way, via the TTY.
