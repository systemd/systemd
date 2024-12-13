---
title: Memory Pressure Handling
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Memory Pressure Handling in systemd

When the system is under memory pressure (i.e. some component of the OS
requires memory allocation but there is only very little or none available),
it can attempt various things to make more memory available again ("reclaim"):

* The kernel can flush out memory pages backed by files on disk, under the
  knowledge that it can reread them from disk when needed again. Candidate
  pages are the many memory mapped executable files and shared libraries on
  disk, among others.

* The kernel can flush out memory packages not backed by files on disk
  ("anonymous" memory, i.e. memory allocated via `malloc()` and similar calls,
  or `tmpfs` file system contents) if there's swap to write it to.

* Userspace can proactively release memory it allocated but doesn't immediately
  require back to the kernel. This includes allocation caches, and other forms
  of caches that are not required for normal operation to continue.

The latter is what we want to focus on in this document: how to ensure
userspace process can detect mounting memory pressure early and release memory
back to the kernel as it happens, relieving the memory pressure before it
becomes too critical.

The effects of memory pressure during runtime generally are growing latencies
during operation: when a program requires memory but the system is busy writing
out memory to (relatively slow) disks in order make some available, this
generally surfaces in scheduling latencies, and applications and services will
slow down until memory pressure is relieved. Hence, to ensure stable service
latencies it is essential to release unneeded memory back to the kernel early
on.

On Linux the [Pressure Stall Information
(PSI)](https://docs.kernel.org/accounting/psi.html) Linux kernel interface is
the primary way to determine the system or a part of it is under memory
pressure. PSI makes available to userspace a `poll()`-able file descriptor that
gets notifications whenever memory pressure latencies for the system or a
control group grow beyond some level.

`systemd` itself makes use of PSI, and helps applications to do so too.
Specifically:

* Most of systemd's long running components watch for PSI memory pressure
  events, and release allocation caches and other resources once seen.

* systemd's service manager provides a protocol for asking services to monitor
  PSI events and configure the appropriate pressure thresholds.

* systemd's `sd-event` event loop API provides a high-level call
  `sd_event_add_memory_pressure()` enabling programs using it to efficiently
  hook into the PSI memory pressure protocol provided by the service manager,
  with very few lines of code.

## Memory Pressure Service Protocol

If memory pressure handling for a specific service is enabled via
`MemoryPressureWatch=` the memory pressure service protocol is used to tell the
service code about this. Specifically two environment variables are set by the
service manager, and typically consumed by the service:

* The `$MEMORY_PRESSURE_WATCH` environment variable will contain an absolute
  path in the file system to the file to watch for memory pressure events. This
  will usually point to a PSI file such as the `memory.pressure` file of the
  service's cgroup. In order to make debugging easier, and allow later
  extension it is recommended for applications to also allow this path to refer
  to an `AF_UNIX` stream socket in the file system or a FIFO inode in the file
  system. Regardless which of the three types of inodes this absolute path
  refers to, all three are `poll()`-able for memory pressure events. The
  variable can also be set to the literal string `/dev/null`. If so the service
  code should take this as indication that memory pressure monitoring is not
  desired and should be turned off.

* The `$MEMORY_PRESSURE_WRITE` environment variable is optional. If set by the
  service manager it contains Base64 encoded data (that may contain arbitrary
  binary values, including NUL bytes) that should be written into the path
  provided via `$MEMORY_PRESSURE_WATCH` right after opening it. Typically, if
  talking directly to a PSI kernel file this will contain information about the
  threshold settings configurable in the service manager.

When a service initializes it hence should look for
`$MEMORY_PRESSURE_WATCH`. If set, it should try to open the specified path. If
it detects the path to refer to a regular file it should assume it refers to a
PSI kernel file. If so, it should write the data from `$MEMORY_PRESSURE_WRITE`
into the file descriptor (after Base64-decoding it, and only if the variable is
set) and then watch for `POLLPRI` events on it.  If it detects the paths refers
to a FIFO inode, it should open it, write the `$MEMORY_PRESSURE_WRITE` data
into it (as above) and then watch for `POLLIN` events on it. Whenever `POLLIN`
is seen it should read and discard any data queued in the FIFO. If the path
refers to an `AF_UNIX` socket in the file system, the application should
`connect()` a stream socket to it, write `$MEMORY_PRESSURE_WRITE` into it (as
above) and watch for `POLLIN`, discarding any data it might receive.

To summarize:

* If `$MEMORY_PRESSURE_WATCH` points to a regular file: open and watch for
  `POLLPRI`, never read from the file descriptor.

* If `$MEMORY_PRESSURE_WATCH` points to a FIFO: open and watch for `POLLIN`,
  read/discard any incoming data.

* If `$MEMORY_PRESSURE_WATCH` points to an `AF_UNIX` socket: connect and watch
  for `POLLIN`, read/discard any incoming data.

* If `$MEMORY_PRESSURE_WATCH` contains the literal string `/dev/null`, turn off
  memory pressure handling.

(And in each case, immediately after opening/connecting to the path, write the
decoded `$MEMORY_PRESSURE_WRITE` data into it.)

Whenever a `POLLPRI`/`POLLIN` event is seen the service is under memory
pressure. It should use this as hint to release suitable redundant resources,
for example:

* glibc's memory allocation cache, via
  [`malloc_trim()`](https://man7.org/linux/man-pages/man3/malloc_trim.3.html). Similar,
  allocation caches implemented in the service itself.

* Any other local caches, such DNS caches, or web caches (in particular if
  service is a web browser).

* Terminate any idle worker threads or processes.

* Run a garbage collection (GC) cycle, if the runtime environment supports it.

* Terminate the process if idle, and can be automatically started when
  needed next.

Which actions precisely to take depends on the service in question. Note that
the notifications are delivered when memory allocation latency already degraded
beyond some point. Hence when discussing which resources to keep and which to
discard, keep in mind it's typically acceptable that latencies incurred
recovering discarded resources at a later point are acceptable, given that
latencies *already* are affected negatively.

In case the path supplied via `$MEMORY_PRESSURE_WATCH` points to a PSI kernel
API file, or to an `AF_UNIX` opening it multiple times is safe and reliable,
and should deliver notifications to each of the opened file descriptors. This
is specifically useful for services that consist of multiple processes, and
where each of them shall be able to release resources on memory pressure.

The `POLLPRI`/`POLLIN` conditions will be triggered every time memory pressure
is detected, but not continuously. It is thus safe to keep `poll()`-ing on the
same file descriptor continuously, and executing resource release operations
whenever the file descriptor triggers without having to expect overloading the
process.

(Currently, the protocol defined here only allows configuration of a single
"degree" of memory pressure, there's no distinction made on how strong the
pressure is. In future, if it becomes apparent that there's clear need to
extend this we might eventually add different degrees, most likely by adding
additional environment variables such as `$MEMORY_PRESSURE_WRITE_LOW` and
`$MEMORY_PRESSURE_WRITE_HIGH` or similar, which may contain different settings
for lower or higher memory pressure thresholds.)

## Service Manager Settings

The service manager provides two per-service settings that control the memory
pressure handling:

* The
  [`MemoryPressureWatch=`](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#MemoryPressureWatch=)
  setting controls whether to enable the memory pressure protocol for the
  service in question.

* The `MemoryPressureThresholdSec=` setting allows configuring the threshold
  when to signal memory pressure to the services. It takes a time value
  (usually in the millisecond range) that defines a threshold per 1s time
  window: if memory allocation latencies grow beyond this threshold
  notifications are generated towards the service, requesting it to release
  resources.

The `/etc/systemd/system.conf` file provides two settings that may be used to
select the default values for the above settings. If the threshold isn't
configured via the per-service nor system-wide option, it defaults to 100ms.

When memory pressure monitoring is enabled for a service via
`MemoryPressureWatch=` this primarily does three things:

* It enables cgroup memory accounting for the service (this is a requirement
  for per-cgroup PSI)

* It sets the aforementioned two environment variables for processes invoked
  for the service, based on the control group of the service and provided
  settings.

* The `memory.pressure` PSI control group file associated with the service's
  cgroup is delegated to the service (i.e. permissions are relaxed so that
  unprivileged service payload code can open the file for writing).

## Memory Pressure Events in `sd-event`

The
[`sd-event`](https://www.freedesktop.org/software/systemd/man/sd-event.html)
event loop library provides two API calls that encapsulate the
functionality described above:

* The
  [`sd_event_add_memory_pressure()`](https://www.freedesktop.org/software/systemd/man/sd_event_add_memory_pressure.html)
  call implements the service-side of the memory pressure protocol and
  integrates it with an `sd-event` event loop. It reads the two environment
  variables, connects/opens the specified file, writes the specified data to it,
  then watches it for events.

* The `sd_event_trim_memory()` call may be called to trim the calling
  processes' memory. It's a wrapper around glibc's `malloc_trim()`, but first
  releases allocation caches maintained by libsystemd internally. This function
  serves as the default when a NULL callback is supplied to
  `sd_event_add_memory_pressure()`.

When implementing a service using `sd-event`, for automatic memory pressure
handling, it's typically sufficient to add a line such as:

```c
(void) sd_event_add_memory_pressure(event, NULL, NULL, NULL);
```

– right after allocating the event loop object `event`.

## Other APIs

Other programming environments might have native APIs to watch memory
pressure/low memory events. Most notable is probably GLib's
[GMemoryMonitor](https://docs.gtk.org/gio/iface.MemoryMonitor.html). It
currently uses the per-system Linux PSI interface as the backend, but operates
differently than the above: memory pressure events are picked up by a system
service, which then propagates this through D-Bus to the applications. This is
typically less than ideal, since this means each notification event has to
traverse three processes before being handled. This traversal creates
additional latencies at a time where the system is already experiencing adverse
latencies. Moreover, it focuses on system-wide PSI events, even though
service-local ones are generally the better approach.
