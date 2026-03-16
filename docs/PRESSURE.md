---
title: Resource Pressure Handling
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Resource Pressure Handling in systemd

On Linux the [Pressure Stall Information
(PSI)](https://docs.kernel.org/accounting/psi.html) Linux kernel interface
provides a way to monitor resource pressure — situations where tasks are
stalled waiting for a resource to become available. PSI covers three types of
resources:

* **Memory pressure**: tasks are stalled because the system is low on memory
  and the kernel is busy reclaiming it (e.g. writing out pages to swap or
  flushing file-backed pages).

* **CPU pressure**: tasks are stalled waiting for CPU time because the CPU is
  oversubscribed.

* **IO pressure**: tasks are stalled waiting for IO operations to complete
  because the IO subsystem is saturated.

PSI makes available to userspace a `poll()`-able file descriptor that gets
notifications whenever pressure latencies for the system or a control group
grow beyond some configured level.

When the system is under memory pressure, userspace can proactively release
memory it allocated but doesn't immediately require back to the kernel. This
includes allocation caches, and other forms of caches that are not required for
normal operation to continue. Similarly, when CPU or IO pressure is detected,
services can take appropriate action such as reducing parallelism, deferring
background work, or shedding load.

The effects of resource pressure during runtime generally are growing latencies
during operation: applications and services slow down until pressure is
relieved. Hence, to ensure stable service latencies it is essential to detect
pressure early and respond appropriately.

`systemd` itself makes use of PSI, and helps applications to do so too.
Specifically:

* Most of systemd's long running components watch for PSI memory pressure
  events, and release allocation caches and other resources once seen.

* systemd's service manager provides a protocol for asking services to monitor
  PSI events and configure the appropriate pressure thresholds, for memory, CPU,
  and IO pressure independently.

* systemd's `sd-event` event loop API provides high-level calls
  `sd_event_add_memory_pressure()`, `sd_event_add_cpu_pressure()`, and
  `sd_event_add_io_pressure()` enabling programs using it to efficiently hook
  into the PSI pressure protocol provided by the service manager, with very few
  lines of code.

## Pressure Service Protocol

For each resource type, if pressure handling for a specific service is enabled
via the corresponding `*PressureWatch=` setting (i.e. `MemoryPressureWatch=`,
`CPUPressureWatch=`, or `IOPressureWatch=`), two environment variables are set
by the service manager:

* `$MEMORY_PRESSURE_WATCH` / `$CPU_PRESSURE_WATCH` / `$IO_PRESSURE_WATCH` —
  contains an absolute path in the file system to the file to watch for
  pressure events. This will usually point to a PSI file such as the
  `memory.pressure`, `cpu.pressure`, or `io.pressure` file of the service's
  cgroup. In order to make debugging easier, and allow later extension it is
  recommended for applications to also allow this path to refer to an `AF_UNIX`
  stream socket in the file system or a FIFO inode in the file system.
  Regardless of which of the three types of inodes this absolute path refers
  to, all three are `poll()`-able for pressure events. The variable can also be
  set to the literal string `/dev/null`. If so the service code should take this
  as indication that pressure monitoring for this resource is not desired and
  should be turned off.

* `$MEMORY_PRESSURE_WRITE` / `$CPU_PRESSURE_WRITE` / `$IO_PRESSURE_WRITE` —
  optional. If set by the service manager it contains Base64 encoded data (that
  may contain arbitrary binary values, including NUL bytes) that should be
  written into the path provided via the corresponding `*_PRESSURE_WATCH`
  variable right after opening it. Typically, if talking directly to a PSI
  kernel file this will contain information about the threshold settings
  configurable in the service manager.

The protocol works the same for all three resource types. The remainder of this
section uses memory pressure as the example, but the same logic applies to CPU
and IO pressure with the corresponding environment variable names.

When a service initializes it hence should look for
`$MEMORY_PRESSURE_WATCH`. If set, it should try to open the specified path. If
it detects the path to refer to a regular file it should assume it refers to a
PSI kernel file. If so, it should write the data from `$MEMORY_PRESSURE_WRITE`
into the file descriptor (after Base64-decoding it, and only if the variable is
set) and then watch for `POLLPRI` events on it.  If it detects the path refers
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

Whenever a `POLLPRI`/`POLLIN` event is seen the service is under pressure. It
should use this as hint to release suitable redundant resources, for example:

* glibc's memory allocation cache, via
  [`malloc_trim()`](https://man7.org/linux/man-pages/man3/malloc_trim.3.html). Similarly,
  allocation caches implemented in the service itself.

* Any other local caches, such as DNS caches, or web caches (in particular if
  service is a web browser).

* Terminate any idle worker threads or processes.

* Run a garbage collection (GC) cycle, if the runtime environment supports it.

* Terminate the process if idle, and can be automatically started when
  needed next.

Which actions precisely to take depends on the service in question and the type
of pressure. Note that the notifications are delivered when resource latency
already degraded beyond some point. Hence when discussing which resources to
keep and which to discard, keep in mind it's typically acceptable that latencies
incurred recovering discarded resources at a later point are acceptable, given
that latencies *already* are affected negatively.

In case the path supplied via `$MEMORY_PRESSURE_WATCH` points to a PSI kernel
API file, or to an `AF_UNIX` socket, opening it multiple times is safe and reliable,
and should deliver notifications to each of the opened file descriptors. This
is specifically useful for services that consist of multiple processes, and
where each of them shall be able to release resources on memory pressure.

The `POLLPRI`/`POLLIN` conditions will be triggered every time pressure is
detected, but not continuously. It is thus safe to keep `poll()`-ing on the
same file descriptor continuously, and executing resource release operations
whenever the file descriptor triggers without having to expect overloading the
process.

(Currently, the protocol defined here only allows configuration of a single
"degree" of pressure per resource type, there's no distinction made on how
strong the pressure is. In future, if it becomes apparent that there's clear
need to extend this we might eventually add different degrees, most likely by
adding additional environment variables such as `$MEMORY_PRESSURE_WRITE_LOW`
and `$MEMORY_PRESSURE_WRITE_HIGH` or similar, which may contain different
settings for lower or higher pressure thresholds.)

## Service Manager Settings

The service manager provides two per-service settings for each resource type
that control pressure handling:

* `MemoryPressureWatch=` / `CPUPressureWatch=` / `IOPressureWatch=` controls
  whether to enable the pressure protocol for the respective resource type for
  the service in question. See
  [`systemd.resource-control(5)`](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#MemoryPressureWatch=)
  for details.

* `MemoryPressureThresholdSec=` / `CPUPressureThresholdSec=` /
  `IOPressureThresholdSec=` allows configuring the threshold when to signal
  pressure to the services. It takes a time value (usually in the millisecond
  range) that defines a threshold per 2s time window: if resource latencies grow
  beyond this threshold notifications are generated towards the service,
  requesting it to release resources.

The `/etc/systemd/system.conf` file provides two settings for each resource
type that may be used to select the default values for the above settings. If
the threshold isn't configured via the per-service nor system-wide option, it
defaults to 200ms.

When pressure monitoring is enabled for a service this primarily does three
things:

* It enables the corresponding cgroup accounting for the service (this is a
  requirement for per-cgroup PSI).

* It sets the aforementioned two environment variables for processes invoked
  for the service, based on the control group of the service and provided
  settings.

* The corresponding PSI control group file (`memory.pressure`, `cpu.pressure`,
  or `io.pressure`) associated with the service's cgroup is delegated to the
  service (i.e. permissions are relaxed so that unprivileged service payload
  code can open the file for writing).

## Pressure Events in `sd-event`

The
[`sd-event`](https://www.freedesktop.org/software/systemd/man/latest/sd-event.html)
event loop library provides API calls that encapsulate the functionality
described above:

* [`sd_event_add_memory_pressure()`](https://www.freedesktop.org/software/systemd/man/latest/sd_event_add_memory_pressure.html),
  `sd_event_add_cpu_pressure()`, and `sd_event_add_io_pressure()` implement the
  service-side of the pressure protocol for each resource type and integrate it
  with an `sd-event` event loop. Each reads the corresponding two environment
  variables, connects/opens the specified file, writes the specified data to it,
  then watches it for events.

* The `sd_event_trim_memory()` call may be called to trim the calling
  processes' memory. It's a wrapper around glibc's `malloc_trim()`, but first
  releases allocation caches maintained by libsystemd internally. This function
  serves as the default when a NULL callback is supplied to
  `sd_event_add_memory_pressure()`. Note that the default handler for
  `sd_event_add_cpu_pressure()` and `sd_event_add_io_pressure()` is a no-op;
  a custom callback should be provided for CPU and IO pressure to take
  meaningful action.

When implementing a service using `sd-event`, for automatic memory pressure
handling, it's typically sufficient to add a line such as:

```c
(void) sd_event_add_memory_pressure(event, NULL, NULL, NULL);
```

– right after allocating the event loop object `event`. For CPU and IO pressure,
a custom handler should be provided to take appropriate action:

```c
(void) sd_event_add_cpu_pressure(event, NULL, my_cpu_pressure_handler, userdata);
(void) sd_event_add_io_pressure(event, NULL, my_io_pressure_handler, userdata);
```

## Other APIs

Other programming environments might have native APIs to watch memory
pressure/low memory events. Most notable is probably GLib's
[GMemoryMonitor](https://docs.gtk.org/gio/iface.MemoryMonitor.html). As of GLib
2.86.0, it uses the per-cgroup PSI kernel file to monitor for memory pressure,
but does not yet read the environment variables recommended above.

In older versions, it used the per-system Linux PSI interface as the backend, but operated
differently than the above: memory pressure events were picked up by a system
service, which then propagated this through D-Bus to the applications. This was
typically less than ideal, since this means each notification event had to
traverse three processes before being handled. This traversal created
additional latencies at a time where the system is already experiencing adverse
latencies. Moreover, it focused on system-wide PSI events, even though
service-local ones are generally the better approach.
