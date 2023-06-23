---
title: Storage Daemons for the Root File System
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# systemd and Storage Daemons for the Root File System

a.k.a. _Pax Cellae pro Radix Arbor_

(or something like that, my Latin is a bit rusty)

A number of complex storage technologies on Linux (e.g. RAID, volume
management, networked storage) require user space services to run while the
storage is active and mountable. This requirement becomes tricky as soon as the
root file system of the Linux operating system is stored on such storage
technology. Previously no clear path to make this work was available. This text
tries to clear up the resulting confusion, and what is now supported and what
is not.

## A Bit of Background

When complex storage technologies are used as backing for the root file system
this needs to be set up by the initrd, i.e. on Fedora by Dracut. In newer
systemd versions tear-down of the root file system backing is also done by the
initrd: after terminating all remaining running processes and unmounting all
file systems it can (which means excluding the root fs) systemd will jump back
into the initrd code allowing it to unmount the final file systems (and its
storage backing) that could not be unmounted as long as the OS was still
running from the main root file system. The initrd' job is to detach/unmount
the root fs, i.e. inverting the exact commands it used to set them up in the
first place. This is not only cleaner, but also allows for the first time
arbitrary complex stacks of storage technology.

Previous attempts to handle root file system setups with complex storage as
backing usually tried to maintain the root storage with program code stored on
the root storage itself, thus creating a number of dependency loops. Safely
detaching such a root file system becomes messy, since the program code on the
storage needs to stay around longer than the storage, which is technically
contradicting.


## What's new?

As a result, we hereby clarify that we do not support storage technology setups
where the storage daemons are being run from the storage it maintains
itself. In other words: a storage daemon backing the root file system cannot be
stored on the root file system itself.

What we do support instead is that these storage daemons are started from the
initrd, stay running all the time during normal operation and are terminated
only after we returned control back to the initrd and by the initrd. As such,
storage daemons involved with maintaining the root file system storage
conceptually are more like kernel threads than like normal system services:
from the perspective of the init system (i.e. systemd) these services have been
started before systemd got initialized and stay around until after systemd is
already gone. These daemons can only be updated by updating the initrd and
rebooting, a takeover from initrd-supplied services to replacements from the
root file system is not supported.


## What does this mean?

Near the end of system shutdown, systemd executes a small tool called
systemd-shutdown, replacing its own process. This tool (which runs as PID 1, as
it entirely replaces the systemd init process) then iterates through the
mounted file systems and running processes (as well as a couple of other
resources) and tries to unmount/read-only mount/detach/kill them. It continues
to do this in a tight loop as long as this results in any effect. From this
killing spree a couple of processes are automatically excluded: PID 1 itself of
course, as well as all kernel threads. After the killing/unmounting spree
control is passed back to the initrd, whose job is then to unmount/detach
whatever might be remaining.

The same killing spree logic (but not the unmount/detach/read-only logic) is
applied during the transition from the initrd to the main system (i.e. the
"`switch_root`" operation), so that no processes from the initrd survive to the
main system.

To implement the supported logic proposed above (i.e. where storage daemons
needed for the root fs which are started by the initrd stay around during
normal operation and are only killed after control is passed back to the
initrd) we need to exclude these daemons from the shutdown/switch_root killing
spree. To accomplish this the following logic is available starting with
systemd 38:

Processes (run by the root user) whose first character of the zeroth command
line argument is `@` are excluded from the killing spree, much the same way as
kernel threads are excluded too. Thus, a daemon which wants to take advantage
of this logic needs to place the following at the top of its `main()` function:

```c
...
argv[0][0] = '@';
...
```

And that's already it. Note that this functionality is only to be used by
programs running from the initrd, and **not** for programs running from the
root file system itself. Programs which use this functionality and are running
from the root file system are considered buggy since they effectively prohibit
clean unmounting/detaching of the root file system and its backing storage.

_Again: if your code is being run from the root file system, then this logic
suggested above is **NOT** for you. Sorry. Talk to us, we can probably help you
to find a different solution to your problem._

The recommended way to distinguish between run-from-initrd and run-from-rootfs
for a daemon is to check for `/etc/initrd-release` (which exists on all modern
initrd implementations, see the [initrd Interface](INITRD_INTERFACE.md) for
details) which when exists results in `argv[0][0]` being set to `@`, and
otherwise doesn't. Something like this:

```c
#include <unistd.h>

int main(int argc, char *argv[]) {
        ...
        if (access("/etc/initrd-release", F_OK) >= 0)
                argv[0][0] = '@';
        ...
    }
```

Why `@`? Why `argv[0][0]`? First of all, a technique like this is not without
precedent: traditionally Unix login shells set `argv[0][0]` to `-` to clarify
they are login shells. This logic is also very easy to implement. We have been
looking for other ways to mark processes for exclusion from the killing spree,
but could not find any that was equally simple to implement and quick to read
when traversing through `/proc/`. Also, as a side effect replacing the first
character of `argv[0]` with `@` also visually invalidates the path normally
stored in `argv[0]` (which usually starts with `/`) thus helping the
administrator to understand that your daemon is actually not originating from
the actual root file system, but from a path in a completely different
namespace (i.e. the initrd namespace). Other than that we just think that `@`
is a cool character which looks pretty in the ps output... 😎

Note that your code should only modify `argv[0][0]` and leave the comm name
(i.e. `/proc/self/comm`) of your process untouched.

## To which technologies does this apply?

These recommendations apply to those storage daemons which need to stay around
until after the storage they maintain is unmounted. If your storage daemon is
fine with being shut down before its storage device is unmounted you may ignore
the recommendations above.

This all applies to storage technology only, not to daemons with any other
(non-storage related) purposes.

## What else to keep in mind?

If your daemon implements the logic pointed out above it should work nicely
from initrd environments. In many cases it might be necessary to additionally
support storage daemons to be started from within the actual OS, for example
when complex storage setups are used for auxiliary file systems, i.e. not the
root file system, or created by the administrator during runtime. Here are a
few additional notes for supporting these setups:

* If your storage daemon is run from the main OS (i.e. not the initrd) it will
  also be terminated when the OS shuts down (i.e. before we pass control back
  to the initrd). Your daemon needs to handle this properly.

* It is not acceptable to spawn off background processes transparently from
  user commands or udev rules. Whenever a process is forked off on Unix it
  inherits a multitude of process attributes (ranging from the obvious to the
  not-so-obvious such as security contexts or audit trails) from its parent
  process. It is practically impossible to fully detach a service from the
  process context of the spawning process. In particular, systemd tracks which
  processes belong to a service or login sessions very closely, and by spawning
  off your storage daemon from udev or an administrator command you thus make
  it part of its service/login. Effectively this means that whenever udev is
  shut down, your storage daemon is killed too, resp. whenever the login
  session goes away your storage might be terminated as well. (Also note that
  recent udev versions will automatically kill all long running background
  processes forked off udev rules now.) So, in summary: double-forking off
  processes from user commands or udev rules is **NOT** OK!

* To automatically spawn storage daemons from udev rules or administrator
  commands, the recommended technology is socket-based activation as
  implemented by systemd. Transparently for your client code connecting to the
  socket of your storage daemon will result in the storage to be started. For
  that it is simply necessary to inform systemd about the socket you'd like it
  to listen on on behalf of your daemon and minimally modify the daemon to
  receive the listening socket for its services from systemd instead of
  creating it on its own. Such modifications can be minimal, and are easily
  written in a way that does not negatively impact usability on non-systemd
  systems. For more information on making use of socket activation in your
  program consult this blog story: [Socket
  Activation](https://0pointer.de/blog/projects/socket-activation.html)

* Consider having a look at the [initrd Interface of systemd](INITRD_INTERFACE.md).
