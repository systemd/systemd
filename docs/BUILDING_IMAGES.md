---
title: Safely Building Images
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Safely Building Images

In many scenarios OS installations are shipped as pre-built images, that
require no further installation process beyond simple `dd`-ing the image to
disk and booting it up. When building such "golden" OS images for
`systemd`-based OSes a few points should be taken into account.

Most of the points described here are implemented by the
[`mkosi`](https://github.com/systemd/mkosi) OS image builder developed and
maintained by the systemd project. If you are using or working on another image
builder it's recommended to keep the following concepts and recommendations in
mind.

## Resources to Reset

Typically the same OS image shall be deployable in multiple instances, and each
instance should automatically acquire its own identifying credentials on first
boot. For that it's essential to:

1. Remove the
   [`/etc/machine-id`](https://www.freedesktop.org/software/systemd/man/machine-id.html)
   file or write the string `uninitialized\n` into it. This file is supposed to
   carry a 128bit identifier unique to the system. Only when it is reset it
   will be auto-generated on first boot and thus be truly unique. If this file
   is not reset, and carries a valid ID every instance of the system will come
   up with the same ID and that will likely lead to problems sooner or later,
   as many network-visible identifiers are commonly derived from the machine
   ID, for example IPv6 addresses or transient MAC addresses.

2. Remove the `/var/lib/systemd/random-seed` file (see
   [`systemd-random-seed(8)`](https://www.freedesktop.org/software/systemd/man/systemd-random-seed.service.html)),
   which is used to seed the kernel's random pool on boot. If this file is
   shipped pre-initialized, every instance will seed its random pool with the
   same random data that is included in the image, and thus possibly generate
   random data that is more similar to other instances booted off the same
   image than advisable.

3. Remove the `/loader/random-seed` file (see
   [`systemd-boot(7)`](https://www.freedesktop.org/software/systemd/man/systemd-boot.html))
   from the UEFI System Partition (ESP), in case the `systemd-boot` boot loader
   is used in the image.

4. It might also make sense to remove
   [`/etc/hostname`](https://www.freedesktop.org/software/systemd/man/hostname.html)
   and
   [`/etc/machine-info`](https://www.freedesktop.org/software/systemd/man/machine-info.html)
   which carry additional identifying information about the OS image.

5. Remove `/var/lib/systemd/credential.secret` which is used for protecting
   service credentials, see
   [`systemd.exec(5)`](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Credentials)
   and
   [`systemd-creds(1)`](https://www.freedesktop.org/software/systemd/man/systemd-creds.html)
   for details. Note that by removing this file access to previously encrypted
   credentials from this image is lost. The file is automatically generated if
   a new credential is encrypted and the file does not exist yet.

## Boot Menu Entry Identifiers

The
[`kernel-install(8)`](https://www.freedesktop.org/software/systemd/man/kernel-install.html)
logic used to generate
[Boot Loader Specification Type 1](BOOT_LOADER_SPECIFICATION.md) entries by
default uses the machine ID as stored in `/etc/machine-id` for naming boot menu
entries and the directories in the ESP to place kernel images in. This is done
in order to allow multiple installations of the same OS on the same system
without conflicts. However, this is problematic if the machine ID shall be
generated automatically on first boot: if the ID is not known before the first
boot it cannot be used to name the most basic resources required for the boot
process to complete.

Thus, for images that shall acquire their identity on first boot only, it is
required to use a different identifier for naming boot menu entries. To allow
this the `kernel-install` logic knows the generalized *entry* *token* concept,
which can be a freely chosen string to use for identifying the boot menu
resources of the OS. If not configured explicitly it defaults to the machine
ID. The file `/etc/kernel/entry-token` may be used to configure this string
explicitly. Thus, golden image builders should write a suitable identifier into
this file, for example the `IMAGE_ID=` or `ID=` field from
[`/etc/os-release`](https://www.freedesktop.org/software/systemd/man/os-release.html)
(also see below). It is recommended to do this before the `kernel-install`
functionality is invoked (i.e. before the package manager is used to install
packages into the OS tree being prepared), so that the selected string is
automatically used for all entries to be generated.

## Booting with Empty `/var/` and/or Empty Root File System

`systemd` is designed to be able to come up safely and robustly if the `/var/`
file system or even the entire root file system (with exception of `/usr/`,
i.e. the vendor OS resources) is empty (i.e. "unpopulated"). With this in mind
it's relatively easy to build images that only ship a `/usr/` tree, and
otherwise carry no other data, populating the rest of the directory hierarchy
on first boot as needed.

Specifically, the following mechanisms are in place:

1. The `switch-root` logic in systemd, that is used to switch from the initrd
   phase to the host will create the basic OS hierarchy skeleton if missing. It
   will create a couple of directories strictly necessary to boot up
   successfully, plus essential symlinks (such as those necessary for the
   dynamic loader `ld.so` to function).

2. PID 1 will initialize `/etc/machine-id` automatically if not initialized yet
   (see above).

3. The
   [`nss-systemd(8)`](https://www.freedesktop.org/software/systemd/man/nss-systemd.html)
   glibc NSS module ensures the `root` and `nobody` users and groups remain
   resolvable, even without `/etc/passwd` and `/etc/group` around.

4. The
   [`systemd-sysusers(8)`](https://www.freedesktop.org/software/systemd/man/systemd-sysusers.service.html)
   will component automatically populate `/etc/passwd` and `/etc/group` on
   first boot with further necessary system users.

5. The
   [`systemd-tmpfiles(8)`](https://www.freedesktop.org/software/systemd/man/systemd-tmpfiles-setup.service.html)
   component ensures that various files and directories below `/etc/`, `/var/`
   and other places are created automatically at boot if missing. Unlike the
   directories/symlinks created by the `switch-root` logic above this logic is
   extensible by packages, and can adjust access modes, file ownership and
   more. Among others this will also link `/etc/os-release` →
   `/usr/lib/os-release`, ensuring that the OS release information is
   unconditionally accessible through `/etc/os-release`.

6. The
   [`nss-myhostname(8)`](https://www.freedesktop.org/software/systemd/man/nss-myhostname.html)
   glibc NSS module will ensure the local host name as well as `localhost`
   remains resolvable, even without `/etc/hosts` around.

With these mechanisms the hierarchies below `/var/` and `/etc/` can be safely
and robustly populated on first boot, so that the OS can safely boot up. Note
that some auxiliary package are not prepared to operate correctly if their
configuration data in `/etc/` or their state directories in `/var/` are
missing. This can typically be addressed via `systemd-tmpfiles` lines that
ensure the missing files and directories are created if missing. In particular,
configuration files that are necessary for operation can be automatically
copied or symlinked from the `/usr/share/factory/etc/` tree via the `C` or `L`
line types. That said, we recommend that all packages safely fall back to
internal defaults if their configuration is missing, making such additional
steps unnecessary.

Note that while `systemd` itself explicitly supports booting up with entirely
unpopulated images (`/usr/` being the only required directory to be populated)
distributions might not be there yet: depending on your distribution further,
manual work might be required to make this scenario work.

## Adapting OS Images to Storage

Typically, if an image is `dd`-ed onto a target disk it will be minimal:
i.e. only consist of necessary vendor data, and lack "payload" data, that shall
be individual to the system, and dependent on host parameters. On first boot,
the OS should take possession of the backing storage as necessary, dynamically
using available space. Specifically:

1. Additional partitions should be created, that make no sense to ship
   pre-built in the image. For example `/tmp/` or `/home/` partitions, or even
   `/var/` or the root file system (see above).

2. Additional partitions should be created that shall function as A/B
   secondaries for partitions shipped in the original image. In other words: if
   the `/usr/` file system shall be updated in an A/B fashion it typically
   makes sense to ship the original A file system in the deployed image, but
   create the B partition on first boot.

3. Partitions covering only a part of the disk should be grown to the full
   extent of the disk.

4. File systems in uninitialized partitions should be formatted with a file
   system of choice.

5. File systems covering only a part of a partition should be grown to the full
   extent of the partition.

6. Partitions should be encrypted with cryptographic keys generated locally on
   the machine the system is first booted on, ensuring these keys remain local
   and are not shared with any other instance of the OS image.

Or any combination of the above: i.e. first create a partition, then encrypt
it, then format it.

`systemd` provides multiple tools to implement the above logic:

1. The
   [`systemd-repart(8)`](https://www.freedesktop.org/software/systemd/man/systemd-repart.service.html)
   component may manipulate GPT partition tables automatically on boot, growing
   partitions or adding in partitions taking the backing storage size into
   account. It can also encrypt partitions automatically it creates (even bind
   to TPM2, automatically) and populate partitions from various sources. It
   does this all in a robust fashion so that aborted invocations will not leave
   incompletely set up partitions around.

2. The
   [`systemd-growfs@(8).service`](https://www.freedesktop.org/software/systemd/man/systemd-growfs.html)
   tool can automatically grow a file system to the partition it is contained
   in. The `x-systemd.growfs` mount option in `/etc/fstab` is sufficient to
   enable this logic for specific mounts. Alternatively appropriately set up
   partitions can set GPT partition flag 59 to request this behaviour, see the
   [Discoverable Partitions Specification](DISCOVERABLE_PARTITIONS.md) for
   details. If the file system is already grown it executes no operation.

3. Similar, the `systemd-makefs@.service` and `systemd-makeswap@.service`
   services can format file systems and swap spaces before first use, if they
   carry no file system signature yet. The `x-systemd.makefs` mount option in
   `/etc/fstab` may be used to request this functionality.

## Provisioning Image Settings

While a lot of work has gone into ensuring `systemd` systems can safely boot
with unpopulated `/etc/` trees, it sometimes is desirable to set a couple of
basic settings *after* `dd`-ing the image to disk, but *before* first boot. For
this the tool
[`systemd-firstboot(1)`](https://www.freedesktop.org/software/systemd/man/systemd-firstboot.html)
can be useful, with its `--image=` switch. It may be used to set very basic
settings, such as the root password or hostname on an OS disk image or
installed block device.

## Distinguishing First Boot

For various purposes it's useful to be able to distinguish the first boot-up of
the system from later boot-ups (for example, to set up TPM hardware
specifically, or register a system somewhere). `systemd` provides mechanisms to
implement that. Specifically, the `ConditionFirstBoot=` and `AssertFirstBoot=`
settings may be used to conditionalize units to only run on first boot. See
[`systemd.unit(5)`](https://www.freedesktop.org/software/systemd/man/systemd.unit.html#ConditionFirstBoot=)
for details.

A special target unit `first-boot-complete.target` may be used as milestone to
safely handle first boots where the system is powered off too early: if the
first boot process is aborted before this target is reached, the following boot
process will be considered a first boot, too. Once the target is reached,
subsequent boots will not be considered first boots anymore, even if the boot
process is aborted immediately after. Thus, services that must complete fully
before a system shall be considered fully past the first boot should be ordered
before this target unit.

Whether a system will come up in first boot state or not is derived from the
initialization status of `/etc/machine-id`: if the file already carries a valid
ID the system is already past the first boot. If it is not initialized yet it
is still considered in the first boot state. For details see
[`machine-id(5)`](https://www.freedesktop.org/software/systemd/man/machine-id.html).

## Image Metadata

Typically, when operating with golden disk images it is useful to be able to
identify them and their version. For this the two fields `IMAGE_ID=` and
`IMAGE_VERSION=` have been defined in
[`os-release(5)`](https://www.freedesktop.org/software/systemd/man/os-release.html). These
fields may be accessed from unit files and similar via the `%M` and `%A`
specifiers.

Depending on how the images are put together it might make sense to leave the
OS distribution's `os-release` file as is in `/usr/lib/os-release` but to
replace the usual `/etc/os-release` symlink with a regular file that extends
the distribution's file with one augmented with these two additional
fields.

## Links

[`machine-id(5)`](https://www.freedesktop.org/software/systemd/man/machine-id.html)<br>
[`systemd-random-seed(8)`](https://www.freedesktop.org/software/systemd/man/systemd-random-seed.service.html)<br>
[`os-release(5)`](https://www.freedesktop.org/software/systemd/man/os-release.html)<br>
[Boot Loader Specification](BOOT_LOADER_SPECIFICATION.md)<br>
[Discoverable Partitions Specification](DISCOVERABLE_PARTITIONS.md)<br>
[`mkosi`](https://github.com/systemd/mkosi)<br>
[`systemd-boot(7)`](https://www.freedesktop.org/software/systemd/man/systemd-boot.html)<br>
[`systemd-repart(8)`](https://www.freedesktop.org/software/systemd/man/systemd-repart.service.html)<br>
[`systemd-growfs@(8).service`](https://www.freedesktop.org/software/systemd/man/systemd-growfs.html)<br>
