---
title: Portable Services Introduction
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Portable Services Introduction

systemd (since version 239) supports a concept of "Portable Services".
"Portable Services" are a delivery method for system services that uses
two specific features of container management:

1. Applications are bundled. I.e. multiple services, their binaries and all
   their dependencies are packaged in an image, and are run directly from it.

2. Stricter default security policies, i.e. sand-boxing of applications.

The primary tool for interacting with Portable Services is `portablectl`,
and they are managed by the `systemd-portabled` service.

Portable services don't bring anything inherently new to the table. All they do
is put together known concepts to cover a specific set of use-cases in a
slightly nicer way.

## So, what *is* a "Portable Service"?

A portable service is ultimately just an OS tree, either inside of a directory,
or inside a raw disk image containing a Linux file system. This tree is called
the "image". It can be "attached" or "detached" from the system. When
"attached", specific systemd units from the image are made available on the
host system, then behaving pretty much exactly like locally installed system
services. When "detached", these units are removed again from the host, leaving
no artifacts around (except maybe messages they might have logged).

The OS tree/image can be created with any tool of your choice. For example, you
can use `dnf --installroot=` if you like, or `debootstrap`, the image format is
entirely generic, and doesn't have to carry any specific metadata beyond what
distribution images carry anyway. Or to say this differently: the image format
doesn't define any new metadata as unit files and OS tree directories or disk
images are already sufficient, and pretty universally available these days. One
particularly nice tool for creating suitable images is
[mkosi](https://github.com/systemd/mkosi), but many other existing tools will
do too.

Portable services may also be constructed from layers, similarly to container
environments. See [Extension Images](#extension-images) below.

If you so will, "Portable Services" are a nicer way to manage chroot()
environments, with better security, tooling and behavior.

## Where's the difference to a "Container"?

"Container" is a very vague term, after all it is used for
systemd-nspawn/LXC-type OS containers, for Docker/rkt-like micro service
containers, and even certain 'lightweight' VM runtimes.

"Portable services" do not provide a fully isolated environment to the payload,
like containers mostly intend to. Instead, they are more like regular system
services, can be controlled with the same tools, are exposed the same way in
all infrastructure, and so on. The main difference is that they use a different
root directory than the rest of the system. Hence, the intent is not to run
code in a different, isolated environment from the host — like most containers
would — but to run it in the same environment, but with stricter access
controls on what the service can see and do.

One point of differentiation: since programs running as "portable services" are
pretty much regular system services, they won't run as PID 1 (like they would
under Docker), but as normal processes. A corollary of that is that they aren't
supposed to manage anything in their own environment (such as the network) as
the execution environment is mostly shared with the rest of the system.

The primary focus use-case of "portable services" is to extend the host system
with encapsulated extensions, but provide almost full integration with the rest
of the system, though possibly restricted by security knobs. This focus
includes system extensions otherwise sometimes called "super-privileged
containers".

Note that portable services are only available for system services, not for
user services (i.e. the functionality cannot be used for the stuff
bubblewrap/flatpak is focusing on).

## Mode of Operation

If you have a portable service image, maybe in a raw disk image called
`foobar_0.7.23.raw`, then attaching the services to the host is as easy as:

```
# portablectl attach foobar_0.7.23.raw
```

This command does the following:

1. It dissects the image, checks and validates the `os-release` file of the
   image, and looks for all included unit files.

2. It copies out all unit files with a suffix of `.service`, `.socket`,
   `.target`, `.timer` and `.path`. whose name begins with the image's name
   (with `.raw` removed), truncated at the first underscore if there is one.
   This prefix name generated from the image name must be followed by a ".",
   "-" or "@" character in the unit name. Or in other words, given the image
   name of `foobar_0.7.23.raw` all unit files matching
   `foobar-*.{service|socket|target|timer|path}`,
   `foobar@.{service|socket|target|timer|path}` as well as
   `foobar.*.{service|socket|target|timer|path}` and
   `foobar.{service|socket|target|timer|path}` are copied out. These unit files
   are placed in `/etc/systemd/system.attached/` (which is part of the normal
   unit file search path of PID 1, and thus loaded exactly like regular unit
   files). Within the images the unit files are looked for at the usual
   locations, i.e. in `/usr/lib/systemd/system/` and `/etc/systemd/system/` and
   so on, relative to the image's root.

3. For each such unit file a drop-in file is created. Let's say
   `foobar-waldo.service` was one of the unit files copied to
   `/etc/systemd/system.attached/`, then a drop-in file
   `/etc/systemd/system.attached/foobar-waldo.service.d/20-portable.conf` is
   created, containing a few lines of additional configuration:

   ```
   [Service]
   RootImage=/path/to/foobar.raw
   Environment=PORTABLE=foobar
   LogExtraFields=PORTABLE=foobar
   ```

4. For each such unit a "profile" drop-in is linked in. This "profile" drop-in
   generally contains security options that lock down the service. By default
   the `default` profile is used, which provides a medium level of security.
   There's also `trusted`, which runs the service with no restrictions, i.e. in
   the host file system root and with full privileges. The `strict` profile
   comes with the toughest security restrictions. Finally, `nonetwork` is like
   `default` but without network access. Users may define their own profiles
   too (or modify the existing ones).

And that's already it.

Note that the images need to stay around (and in the same location) as long as the
portable service is attached. If an image is moved, the `RootImage=` line
written to the unit drop-in would point to an non-existent path, and break
access to the image.

The `portablectl detach` command executes the reverse operation: it looks for
the drop-ins and the unit files associated with the image, and removes them.

Note that `portablectl attach` won't enable or start any of the units it copies
out by default, but `--enable` and `--now` parameter are available as shortcuts.
The same is true for the opposite `detach` operation.

The `portablectl reattach` command combines a `detach` with an `attach`. It is
useful in case an image gets upgraded, as it allows performing a `restart`
operation on the units instead of `stop` plus `start`, thus providing lower
downtime and avoiding losing runtime state associated with the unit such as the
file descriptor store.

## Requirements on Images

Note that portable services don't introduce any new image format, but most OS
images should just work the way they are. Specifically, the following
requirements are made for an image that can be attached/detached with
`portablectl`.

1. It must contain an executable that shall be invoked, along with all its
   dependencies. Any binary code needs to be compiled for an architecture
   compatible with the host.

2. The image must either be a plain sub-directory (or btrfs subvolume)
   containing the binaries and its dependencies in a classic Linux OS tree, or
   must be a raw disk image either containing only one, naked file system, or
   an image with a partition table understood by the Linux kernel with only a
   single partition defined, or alternatively, a GPT partition table with a set
   of properly marked partitions following the
   [Discoverable Partitions Specification](DISCOVERABLE_PARTITIONS.md).

3. The image must at least contain one matching unit file, with the right name
   prefix and suffix (see above). The unit file is searched in the usual paths,
   i.e. primarily /etc/systemd/system/ and /usr/lib/systemd/system/ within the
   image. (The implementation will check a couple of other paths too, but it's
   recommended to use these two paths.)

4. The image must contain an os-release file, either in `/etc/os-release` or
   `/usr/lib/os-release`. The file should follow the standard format.

5. The image must contain the files `/etc/resolv.conf` and `/etc/machine-id`
   (empty files are ok), they will be bind mounted from the host at runtime.

6. The image must contain directories `/proc/`, `/sys/`, `/dev/`, `/run/`,
   `/tmp/`, `/var/tmp/` that can be mounted over with the corresponding version
   from the host.

7. The OS might require other files or directories to be in place. For example,
   if the image is built based on glibc, the dynamic loader needs to be
   available in `/lib/ld-linux.so.2` or `/lib64/ld-linux-x86-64.so.2` (or
   similar, depending on architecture), and if the distribution implements a
   merged `/usr/` tree, this means `/lib` and/or `/lib64` need to be symlinks
   to their respective counterparts below `/usr/`. For details see your
   distribution's documentation.

Note that images created by tools such as `debootstrap`, `dnf --installroot=`
or `mkosi` generally satisfy all of the above. If you wonder what the most
minimal image would be that complies with the requirements above, it could
consist of this:

```
/usr/bin/minimald                            # a statically compiled binary
/usr/lib/systemd/system/minimal-test.service # the unit file for the service, with ExecStart=/usr/bin/minimald
/usr/lib/os-release                          # an os-release file explaining what this is
/etc/resolv.conf                             # empty file to mount over with host's version
/etc/machine-id                              # ditto
/proc/                                       # empty directory to use as mount point for host's API fs
/sys/                                        # ditto
/dev/                                        # ditto
/run/                                        # ditto
/tmp/                                        # ditto
/var/tmp/                                    # ditto
```

And that's it.

Note that qualifying images do not have to contain an init system of their
own. If they do, it's fine, it will be ignored by the portable service logic,
but they generally don't have to, and it might make sense to avoid any, to keep
images minimal.

If the image is writable, and some of the files or directories that are
overmounted from the host do not exist yet they will be automatically created.
On read-only, immutable images (e.g. squashfs images) all files and directories
to over-mount must exist already.

Note that as no new image format or metadata is defined, it's very
straightforward to define images than can be made use of in a number of
different ways. For example, by using `mkosi -b` you can trivially build a
single, unified image that:

1. Can be attached as portable service, to run any container services natively
   on the host.

2. Can be run as OS container, using `systemd-nspawn`, by booting the image
   with `systemd-nspawn -i -b`.

3. Can be booted directly as VM image, using a generic VM executor such as
   `virtualbox`/`qemu`/`kvm`

4. Can be booted directly on bare-metal systems.

Of course, to facilitate 2, 3 and 4 you need to include an init system in the
image. To facilitate 3 and 4 you also need to include a boot loader in the
image. As mentioned, `mkosi -b` takes care of all of that for you, but any
other image generator should work too.

The
[os-release(5)](https://www.freedesktop.org/software/systemd/man/os-release.html)
file may optionally be extended with a `PORTABLE_PREFIXES=` field listing all
supported portable service prefixes for the image (see above). This is useful
for informational purposes (as it allows recognizing portable service images
from their contents as such), but is also useful to protect the image from
being used under a wrong name and prefix. This is particularly relevant if the
images are cryptographically authenticated (via Verity or a similar mechanism)
as this way the (not necessarily authenticated) image file name can be
validated against the (authenticated) image contents. If the field is not
specified the image will work fine, but is not necessarily recognizable as
portable service image, and any set of units included in the image may be
attached, there are no restrictions enforced.

## Extension Images

Portable services can be delivered as one or multiple images that extend the base
image, and are combined with OverlayFS at runtime, when they are attached. This
enables a workflow that splits the base 'runtime' from the daemon, so that multiple
portable services can share the same 'runtime' image (libraries, tools) without
having to include everything each time, with the layering happening only at runtime.
The `--extension` parameter of `portablectl` can be used to specify as many upper
layers as desired. On top of the requirements listed in the previous section, the
following must be also be observed:

1. The base/OS image must contain an `os-release file`, either in `/etc/os-release`
   or `/usr/lib/os-release`, in the standard format.

2. The upper extension images must contain an extension-release file in
   `/usr/lib/extension-release.d/`, with an `ID=` and `SYSEXT_LEVEL=`/`VERSION_ID=`
   matching the base image.

3. The base/OS image does not need to have any unit files.

4. The upper extension images must contain at least one matching unit file
   each, with the right name prefix and suffix (see above).

5. As with the base/OS image, each upper extension image must be a plain
   sub-directory, btrfs subvolume, or a raw disk image.

```
# portablectl attach --extension foobar_0.7.23.raw debian-runtime_11.1.raw foobar
# portablectl attach --extension barbaz_7.0.23/ debian-runtime_11.1.raw barbaz
```

## Execution Environment

Note that the code in portable service images is run exactly like regular
services. Hence there's no new execution environment to consider. And, unlike
Docker would do it, as these are regular system services they aren't run as PID
1 either, but with regular PID values.

## Access to host resources

If services shipped with this mechanism shall be able to access host resources
(such as files or AF_UNIX sockets for IPC), use the normal `BindPaths=` and
`BindReadOnlyPaths=` settings in unit files to mount them in. In fact the
`default` profile mentioned above makes use of this to ensure
`/etc/resolv.conf`, the D-Bus system bus socket or write access to the logging
subsystem are available to the service.

## Instantiation

Sometimes it makes sense to instantiate the same set of services multiple
times. The portable service concept does not introduce a new logic for this. It
is recommended to use the regular systemd unit templating for this, i.e. to
include template units such as `foobar@.service`, so that instantiation is as
simple as:

```
# portablectl attach foobar_0.7.23.raw
# systemctl enable --now foobar@instancea.service
# systemctl enable --now foobar@instanceb.service
…
```

The benefit of this approach is that templating works exactly the same for
units shipped with the OS itself as for attached portable services.

## Immutable images with local data

It's a good idea to keep portable service images read-only during normal
operation. In fact all but the `trusted` profile will default to this kind of
behaviour, by setting the `ProtectSystem=strict` option. In this case writable
service data may be placed on the host file system. Use `StateDirectory=` in
the unit files to enable such behaviour and add a local data directory to the
services copied onto the host.

## Links

[`portablectl(1)`](https://www.freedesktop.org/software/systemd/man/portablectl.html)<br>
[`systemd-portabled.service(8)`](https://www.freedesktop.org/software/systemd/man/systemd-portabled.service.html)<br>
[Walkthrough for Portable Services](https://0pointer.net/blog/walkthrough-for-portable-services.html)<br>
[Repo with examples](https://github.com/systemd/portable-walkthrough)
