---
title: Container Interface
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# The Container Interface

Also consult [Writing Virtual Machine or Container Managers](/WRITING_VM_AND_CONTAINER_MANAGERS).

systemd has a number of interfaces for interacting with container managers,
when systemd is used inside of an OS container. If you work on a container
manager, please consider supporting the following interfaces.

## Execution Environment

1. If the container manager wants to control the hostname for a container
   running systemd it may just set it before invoking systemd, and systemd will
   leave it unmodified when there is no hostname configured in `/etc/hostname`
   (that file overrides whatever is pre-initialized by the container manager).

2. Make sure to pre-mount `/proc/`, `/sys/`, and `/sys/fs/selinux/` before
   invoking systemd, and mount `/sys/`, `/sys/fs/selinux/` and `/proc/sys/`
   read-only (the latter via e.g. a read-only bind mount on itself) in order
   to prevent the container from altering the host kernel's configuration
   settings. (As a special exception, if your container has network namespaces
   enabled, feel free to make `/proc/sys/net/` writable. If it also has user, ipc,
   uts and pid namespaces enabled, the entire `/proc/sys` can be left writable).
   systemd and various other subsystems (such as the SELinux userspace) have
   been modified to behave accordingly when these file systems are read-only.
   (It's OK to mount `/sys/` as `tmpfs` btw, and only mount a subset of its
   sub-trees from the real `sysfs` to hide `/sys/firmware/`, `/sys/kernel/` and
   so on. If you do that, make sure to mark `/sys/` read-only, as that
   condition is what systemd looks for, and is what is considered to be the API
   in this context.)

3. Pre-mount `/dev/` as (container private) `tmpfs` for the container and bind
   mount some suitable TTY to `/dev/console`. If this is a pty, make sure to
   not close the controlling pty during systemd's lifetime. PID 1 will close
   ttys, to avoid being killed by SAK. It only opens ttys for the time it
   actually needs to print something. Also, make sure to create device nodes
   for `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`,
   `/dev/tty`, `/dev/ptmx` in `/dev/`. It is not necessary to create `/dev/fd`
   or `/dev/stdout`, as systemd will do that on its own. Make sure to set up a
   `BPF_PROG_TYPE_CGROUP_DEVICE` BPF program — on cgroupv2 — or the `devices`
   cgroup controller — on cgroupv1 — so that no other devices but these may be
   created in the container. Note that many systemd services use
   `PrivateDevices=`, which means that systemd will set up a private `/dev/`
   for them for which it needs to be able to create these device nodes.
   Dropping `CAP_MKNOD` for containers is hence generally not advisable, but
   see below.

4. `systemd-udevd` is not available in containers (and refuses to start), and
   hence device dependencies are unavailable. The `systemd-udevd` unit files
   will check for `/sys/` being read-only, as an indication whether device
   management can work. Therefore make sure to mount `/sys/` read-only in the
   container (see above). Various clients of `systemd-udevd` also check the
   read-only state of `/sys/`, including PID 1 itself and `systemd-networkd`.

5. If systemd detects it is run in a container it will spawn a single shell on
   `/dev/console`, and not care about VTs or multiple gettys on VTs. (But see
   `$container_ttys` below.)

6. Either pre-mount all cgroup hierarchies in full into the container, or leave
   that to systemd which will do so if they are missing. Note that it is
   explicitly *not* OK to just mount a sub-hierarchy into the container as that
   is incompatible with `/proc/$PID/cgroup` (which lists full paths). Also the
   root-level cgroup directories tend to be quite different from inner
   directories, and that distinction matters. It is OK however, to mount the
   "upper" parts read-only of the hierarchies, and only allow write-access to
   the cgroup sub-tree the container runs in. It's also a good idea to mount
   all controller hierarchies with exception of `name=systemd` fully read-only
   (this only applies to cgroupv1, of course), to protect the controllers from
   alteration from inside the containers. Or to turn this around: only the
   cgroup sub-tree of the container itself (on cgroupv2 in the unified
   hierarchy, and on cgroupv1 in the `name=systemd` hierarchy) may be writable
   to the container.

7. Create the control group root of your container by either running your
   container as a service (in case you have one container manager instance per
   container instance) or creating one scope unit for each container instance
   via systemd's transient unit API (in case you have one container manager
   that manages all instances. Either way, make sure to set `Delegate=yes` in
   it. This ensures that the unit you created will be part of all cgroup
   controllers (or at least the ones systemd understands). The latter may also
   be done via `systemd-machined`'s `CreateMachine()` API. Make sure to use the
   cgroup path systemd put your process in for all operations of the container.
   Do not add new cgroup directories to the top of the tree. This will not only
   confuse systemd and the admin, but also prevent your implementation from
   being "stackable".

## Environment Variables

1. To allow systemd (and other programs) to identify that it is executed within
   a container, please set the `$container` environment variable for PID 1 in
   the container to a short lowercase string identifying your
   implementation. With this in place the `ConditionVirtualization=` setting in
   unit files will work properly. Example: `container=lxc-libvirt`

2. systemd has special support for allowing container managers to initialize
   the UUID for `/etc/machine-id` to some manager supplied value. This is only
   enabled if `/etc/machine-id` is empty (i.e. not yet set) at boot time of the
   container. The container manager should set `$container_uuid` as environment
   variable for the container's PID 1 to the container UUID. (This is similar
   to the effect of `qemu`'s `-uuid` switch). Note that you should pass only a
   UUID here that is actually unique (i.e. only one running container should
   have a specific UUID), and gets changed when a container gets duplicated.
   Also note that systemd will try to persistently store the UUID in
   `/etc/machine-id` (if writable) when this option is used, hence you should
   always pass the same UUID here. Keeping the externally used UUID for a
   container and the internal one in sync is hopefully useful to minimize
   surprise for the administrator.

3. systemd can automatically spawn login gettys on additional ptys. A container
   manager can set the `$container_ttys` environment variable for the
   container's PID 1 to tell it on which ptys to spawn gettys. The variable
   should take a space separated list of pty names, without the leading `/dev/`
   prefix, but with the `pts/` prefix included. Note that despite the
   variable's name you may only specify ptys, and not other types of ttys. Also
   you need to specify the pty itself, a symlink will not suffice. This is
   implemented in
   [systemd-getty-generator(8)](https://www.freedesktop.org/software/systemd/man/latest/systemd-getty-generator.html).
   Note that this variable should not include the pty that `/dev/console` maps
   to if it maps to one (see below). Example: if the container receives
   `container_ttys=pts/7 pts/8 pts/14` it will spawn three additional login
   gettys on ptys 7, 8, and 14.

4. To allow applications to detect the OS version and other metadata of the host
   running the container manager, if this is considered desirable, please parse
   the host's `/etc/os-release` and set a `$container_host_<key>=<VALUE>`
   environment variable for the ID fields described by the [os-release
   interface](https://www.freedesktop.org/software/systemd/man/latest/os-release.html), eg:
   `$container_host_id=debian`
   `$container_host_build_id=2020-06-15`
   `$container_host_variant_id=server`
   `$container_host_version_id=10`

5. systemd supports passing immutable binary data blobs with limited size and
   restricted access to services via the `ImportCredential=`, `LoadCredential=`
   and `SetCredential=` settings. The same protocol may be used to pass credentials
   from the container manager to systemd itself. The credential data should be
   placed in some location (ideally a read-only and non-swappable file system,
   like 'ramfs'), and the absolute path to this directory exported in the
   `$CREDENTIALS_DIRECTORY` environment variable. If the container managers
   does this, the credentials passed to the service manager can be propagated
   to services via `LoadCredential=` or `ImportCredential=` (see ...). The
   container manager can choose any path, but `/run/host/credentials` is
   recommended.

## Advanced Integration

1. Consider syncing `/etc/localtime` from the host file system into the
   container. Make it a relative symlink to the containers's zoneinfo dir, as
   usual. Tools rely on being able to determine the timezone setting from the
   symlink value, and making it relative looks nice even if people list the
   container's `/etc/` from the host.

2. Make the container journal available in the host, by automatically
   symlinking the container journal directory into the host journal directory.
   More precisely, link `/var/log/journal/<container-machine-id>` of the
   container into the same dir of the host. Administrators can then
   automatically browse all container journals (correctly interleaved) by
   issuing `journalctl -m`. The container machine ID can be determined from
   `/etc/machine-id` in the container.

3. If the container manager wants to cleanly shut down the container, it might
   be a good idea to send `SIGRTMIN+3` to its init process. systemd will then
   do a clean shutdown. Note however, that since only systemd understands
   `SIGRTMIN+3` like this, this might confuse other init systems. A container
   manager may implement the `$NOTIFY_SOCKET` protocol mentioned below in which
   case it will receive a notification message `X_SYSTEMD_SIGNALS_LEVEL=2` that
   indicates if and when these additional signal handlers are installed. If
   these signals are sent to the container's PID 1 before this notification
   message is sent they might not be handled correctly yet.

4. To support [Socket Activated
   Containers](https://0pointer.de/blog/projects/socket-activated-containers.html)
   the container manager should be capable of being run as a systemd
   service. It will then receive the sockets starting with FD 3, the number of
   passed FDs in `$LISTEN_FDS` and its PID as `$LISTEN_PID`. It should take
   these and pass them on to the container's init process, also setting
   $LISTEN_FDS and `$LISTEN_PID` (basically, it can just leave the FDs and
   `$LISTEN_FDS` untouched, but it needs to adjust `$LISTEN_PID` to the
   container init process). That's all that's necessary to make socket
   activation work. The protocol to hand sockets from systemd to services is
   hence the same as from the container manager to the container systemd. For
   further details see the explanations of
   [sd_listen_fds(1)](https://0pointer.de/public/systemd-man/sd_listen_fds.html)
   and the [blog story for service
   developers](https://0pointer.de/blog/projects/socket-activation.html).

5. Container managers should stay away from the cgroup hierarchy outside of the
   unit they created for their container. That's private property of systemd,
   and no other code should modify it.

6. systemd running inside the container can report when boot-up is complete,
   boot progress and functionality as well as various other bits of system
   information using the `sd_notify()` protocol that is also used when a
   service wants to tell the service manager about readiness. A container
   manager can set the `$NOTIFY_SOCKET` environment variable to a suitable
   socket path to make use of this functionality. (Also see information about
   `/run/host/notify` below, as well as the Readiness Protocol section on
   [systemd(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd.html)

## Networking

1. Inside of a container, if a `veth` link is named `host0`, `systemd-networkd`
   running inside of the container will by default run DHCPv4, DHCPv6, and
   IPv4LL clients on it. It is thus recommended that container managers that
   add a `veth` link to a container name it `host0`, to get an automatically
   configured network, with no manual setup.

2. Outside of a container, if a `veth` link is prefixed "ve-", `systemd-networkd`
   will by default run DHCPv4 and DHCPv6 servers on it, as well as IPv4LL. It
   is thus recommended that container managers that add a `veth` link to a
   container name the external side `ve-` + the container name.

3. It is recommended to configure stable MAC addresses for container `veth`
   devices, for example, hashed out of the container names. That way it is more
   likely that DHCP and IPv4LL will acquire stable addresses.

## The `/run/host/` Hierarchy

Container managers may place certain resources the manager wants to provide to
the container payload below the `/run/host/` hierarchy. This hierarchy should
be mostly immutable (possibly some subdirs might be writable, but the top-level
hierarchy — and probably most subdirs should be read-only to the
container). Note that this hierarchy is used by various container managers, and
care should be taken to avoid naming conflicts. `systemd` (and in particular
`systemd-nspawn`) use the hierarchy for the following resources:

1. The `/run/host/incoming/` directory mount point is configured for `MS_SLAVE`
   mount propagation with the host, and is used as intermediary location for
   mounts to establish in the container, for the implementation of `machinectl
   bind`. Container payload should usually not directly interact with this
   directory: it's used by code outside the container to insert mounts inside
   it only, and is mostly an internal vehicle to achieve this. Other container
   managers that want to implement similar functionality might consider using
   the same directory. Alternatively, the new mount API may be used by the
   container manager to establish new mounts in the container without the need
   for the `/run/host/incoming/` directory.

2. The `/run/host/inaccessible/` directory may be set up by the container
   manager to include six file nodes: `reg`, `dir`, `fifo`, `sock`, `chr`,
   `blk`. These nodes correspond with the six types of file nodes Linux knows
   (with the exceptions of symlinks). Each node should be of the specific type
   and have an all zero access mode, i.e. be inaccessible. The two device node
   types should have major and minor of zero (which are unallocated devices on
   Linux). These nodes are used as mount source for implementing the
   `InaccessiblePath=` setting of unit files, i.e. file nodes to mask this way
   are overmounted with these "inaccessible" inodes, guaranteeing that the file
   node type does not change this way but the nodes still become
   inaccessible. Note that systemd when run as PID 1 in the container payload
   will create these nodes on its own if not passed in by the container
   manager. However, in that case it likely lacks the privileges to create the
   character and block devices nodes (there are fallbacks for this case).

3. The `/run/host/notify` path is a good choice to place the `sd_notify()`
   socket in, that may be used for the container's PID 1 to report to the
   container manager when boot-up is complete. The path used for this doesn't
   matter much as it is communicated via the `$NOTIFY_SOCKET` environment
   variable, following the usual protocol for this, however it's suitable, and
   recommended place for this socket in case ready notification is desired.

4. The `/run/host/os-release` file contains the `/etc/os-release` file of the
   host, i.e. may be used by the container payload to gather limited
   information about the host environment, on top of what `uname -a` reports.

5. The `/run/host/container-manager` file may be used to pass the same
   information as the `$container` environment variable (see above), i.e. a
   short string identifying the container manager implementation. This file
   should be newline terminated. Passing this information via this file has the
   benefit that payload code can easily access it, even when running
   unprivileged without access to the container PID 1's environment block.

6. The `/run/host/container-uuid` file may be used to pass the same information
   as the `$container_uuid` environment variable (see above). This file should
   be newline terminated.

7. The `/run/host/credentials/` directory is a good place to pass credentials
   into the container, using the `$CREDENTIALS_DIRECTORY` protocol, see above.

8. The `/run/host/unix-export/` directory shall be writable from the container
   payload, and is where container payload can bind `AF_UNIX` sockets in that
   shall be *exported* to the host, so that the host can connect to them. The
   container manager should bind mount this directory on the host side
   (read-only ideally), so that the host can connect to contained sockets. This
   is most prominently used by `systemd-ssh-generator` when run in such a
   container to automatically bind an SSH socket into that directory, which
   then can be used to connect to the container.

9. The `/run/host/unix-export/ssh` `AF_UNIX` socket will be automatically bound
   by `systemd-ssh-generator` in the container if possible, and can be used to
   connect to the container.

10. The `/run/host/userdb/` directory may be used to drop-in additional JSON
    user records that `nss-systemd` inside the container shall include in the
    system's user database. This is useful to make host users and their home
    directories automatically accessible to containers in transitive
    fashion. See `nss-systemd(8)` for details.

11. The `/run/host/home/` directory may be used to bind mount host home
    directories of users that shall be made available in the container to. This
    may be used in combination with `/run/host/userdb/` above: one defines the
    user record, the other contains the user's home directory.

## What You Shouldn't Do

1. Do not drop `CAP_MKNOD` from the container. `PrivateDevices=` is a commonly
   used service setting that provides a service with its own, private, minimal
   version of `/dev/`. To set this up systemd in the container needs this
   capability. If you take away the capability, then all services that set this
   flag will cease to work. Use `BPF_PROG_TYPE_CGROUP_DEVICE` BPF programs — on
   cgroupv2 — or the `devices` controller — on cgroupv1 — to restrict what
   device nodes the container can create instead of taking away the capability
   wholesale. (Also see the section about fully unprivileged containers below.)

2. Do not drop `CAP_SYS_ADMIN` from the container. A number of the most
   commonly used file system namespacing related settings, such as
   `PrivateDevices=`, `ProtectHome=`, `ProtectSystem=`, `MountFlags=`,
   `PrivateTmp=`, `ReadWriteDirectories=`, `ReadOnlyDirectories=`,
   `InaccessibleDirectories=`, and `MountFlags=` need to be able to open new
   mount namespaces and the mount certain file systems into them. You break all
   services that make use of these options if you drop the capability. Also
   note that logind mounts `XDG_RUNTIME_DIR` as `tmpfs` for all logged in users
   and that won't work either if you take away the capability. (Also see
   section about fully unprivileged containers below.)

3. Do not cross-link `/dev/kmsg` with `/dev/console`. They are different things,
   you cannot link them to each other.

4. Do not pretend that the real VTs are available in the container. The VT
   subsystem consists of all the devices `/dev/tty[0-9]*`, `/dev/vcs*`,
   `/dev/vcsa*` plus their `sysfs` counterparts. They speak specific `ioctl()`s
   and understand specific escape sequences, that other ptys don't understand.
   Hence, it is explicitly not OK to mount a pty to `/dev/tty1`, `/dev/tty2`,
   `/dev/tty3`. This is explicitly not supported.

5. Don't pretend that passing arbitrary devices to containers could really work
   well. For example, do not pass device nodes for block devices to the
   container. Device access (with the exception of network devices) is not
   virtualized on Linux. Enumeration and probing of meta information from
   `/sys/` and elsewhere is not possible to do correctly in a container. Simply
   adding a specific device node to a container's `/dev/` is *not* *enough* to
   do the job, as `systemd-udevd` and suchlike are not available at all, and no
   devices will appear available or enumerable, inside the container.

6. Don't mount only a sub-tree of the `cgroupfs` into the container. This will not
   work as `/proc/$PID/cgroup` lists full paths and cannot be matched up with
   the actual `cgroupfs` tree visible, then. (You may "prune" some branches
   though, see above.)

7. Do not make `/sys/` writable in the container. If you do,
   `systemd-udevd.service` is started to manage your devices — inside the
   container, but that will cause conflicts and errors given that the Linux
   device model is not virtualized for containers on Linux and thus the
   containers and the host would try to manage the same devices, fighting for
   ownership. Multiple other subsystems of systemd similarly test for `/sys/`
   being writable to decide whether to use `systemd-udevd` or assume that
   device management is properly available on the instance. Among them
   `systemd-networkd` and `systemd-logind`. The conditionalization on the
   read-only state of `/sys/` enables a nice automatism: as soon as `/sys/` and
   the Linux device model are changed to be virtualized properly the container
   payload can make use of that, simply by marking `/sys/` writable. (Note that
   as special exception, the devices in `/sys/class/net/` are virtualized
   already, if network namespacing is used. Thus it is OK to mount the relevant
   sub-directories of `/sys/` writable, but make sure to leave the root of
   `/sys/` read-only.)

8. Do not pass the `CAP_AUDIT_CONTROL`, `CAP_AUDIT_READ`, `CAP_AUDIT_WRITE`
   capabilities to the container, in particular not to those making use of user
   namespaces. The kernel's audit subsystem is still not virtualized for
   containers, and passing these credentials is pointless hence, given the
   actual attempt to make use of the audit subsystem will fail. Note that
   systemd's audit support is partially conditioned on these capabilities, thus
   by dropping them you ensure that you get an entirely clean boot, as systemd
   will make no attempt to use it. If you pass the capabilities to the payload
   systemd will assume that audit is available and works, and some components
   will subsequently fail in various ways. Note that once the kernel learnt
   native support for container-virtualized audit, adding the capability to the
   container description will automatically make the container payload use it.

## Fully Unprivileged Container Payload

First things first, to make this clear: Linux containers are not a security
technology right now. There are more holes in the model than in swiss cheese.

For example: if you do not use user namespacing, and share root and other users
between container and host, the `struct user` structures will be shared between
host and container, and hence `RLIMIT_NPROC` and so of the container users
affect the host and other containers, and vice versa. This is a major security
hole, and actually is a real-life problem: since Avahi sets `RLIMIT_NPROC` of
its user to 2 (to effectively disallow `fork()`ing) you cannot run more than
one Avahi instance on the entire system...

People have been asking to be able to run systemd without `CAP_SYS_ADMIN` and
`CAP_SYS_MKNOD` in the container. This is now supported to some level in
systemd, but we recommend against it (see above). If `CAP_SYS_ADMIN` and
`CAP_SYS_MKNOD` are missing from the container systemd will now gracefully turn
off `PrivateTmp=`, `PrivateNetwork=`, `ProtectHome=`, `ProtectSystem=` and
others, because those capabilities are required to implement these options. The
services using these settings (which include many of systemd's own) will hence
run in a different, less secure environment when the capabilities are missing
than with them around.

With user namespacing in place things get much better. With user namespaces the
`struct user` issue described above goes away, and containers can keep
`CAP_SYS_ADMIN` safely for the user namespace, as capabilities are virtualized
and having capabilities inside a container doesn't mean one also has them
outside.

## Final Words

If you write software that wants to detect whether it is run in a container,
please check `/proc/1/environ` and look for the `container=` environment
variable. Do not assume the environment variable is inherited down the process
tree. It generally is not. Hence check the environment block of PID 1, not your
own. Note though that this file is only accessible to root. systemd hence early
on also copies the value into `/run/systemd/container`, which is readable for
everybody. However, that's a systemd-specific interface and other init systems
are unlikely to do the same.

Note that it is our intention to make systemd systems work flawlessly and
out-of-the-box in containers. In fact, we are interested to ensure that the same
OS image can be booted on a bare system, in a VM and in a container, and behave
correctly each time. If you notice that some component in systemd does not work
in a container as it should, even though the container manager implements
everything documented above, please contact us.
