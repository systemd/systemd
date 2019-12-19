---
title: Discoverable Partitions Specification
category: Concepts
layout: default
---
# The Discoverable Partitions Specification

_TL;DR: Let's automatically discover, mount and enable the root partition,
`/home/`, `/srv/`, `/var/` and `/var/tmp/` and the swap partitions based on
GUID Partition Tables (GPT)!_

The GUID Partition Table (GPT) is mandatory on EFI systems. It allows
identification of partition types with UUIDs. So far Linux has made little use
of this, and mostly just defined one UUID for file system/data partitions and
another one for swap partitions.  With this specification, we introduce
additional partition types to enable automatic discovery of partitions and
their intended mountpoint.  This has many benefits:

* OS installers can automatically discover and make sense of partitions of
  existing Linux installations.
* The OS can discover and mount the necessary file systems with a non-existing
  or incomplete `/etc/fstab` file and without the `root=` kernel command line
  option.
* Container managers (such as nspawn and libvirt-lxc) can decode and set up
  file systems contained in GPT disk images automatically and mount them to the
  right places, thus allowing booting the same, identical images on bare-metal
  and in Linux containers. This enables true, natural portability of disk
  images between physical machines and Linux containers.
* As a help to administrators and users partition manager tools can show more
  descriptive information about partitions tables.

Note that the OS side of this specification is currently implemented in
[systemd](http://systemd.io/) 211 and newer in the
[systemd-auto-gpt-generator(8)](http://www.freedesktop.org/software/systemd/man/systemd-gpt-auto-generator.html)
generator tool. Note that automatic discovery of the root only works if the
boot loader communicates this information to the OS, by implementing the [Boot
Loader
Interface](https://systemd.io/BOOT_LOADER_INTERFACE).

## Defined Partition Type UUIDs

<table>

<tr>
<th>Partition Type UUID</th>
<th>Name</th>
<th>Allowed File Systems</th>
<th>Explanation</th>
</tr>

<tr>
<td><nobr><tt>44479540-f297-41b2-9af7-d131d5f0458a</tt></nobr></td>
<td><nobr><i>Root Partition (x86)</i></nobr></td>
<td rowspan="5">Any native, optionally in LUKS</td>
<td rowspan="5">On systems with matching architecture, the first partition with
this type UUID on the disk containing the active EFI ESP is automatically
mounted to the root directory <tt>/</tt>.  If the partition is encrypted with
LUKS or has dm-verity integrity data (see below), the device mapper file will
be named <tt>/dev/mapper/root</tt>.</td>
</tr>

<tr>
<td><nobr><tt>4f68bce3-e8cd-4db1-96e7-fbcaf984b709</tt></nobr></td>
<td><nobr><i>Root Partition (x86-64)</i></bobr></td>
</tr>

<tr>
<td><nobr><tt>69dad710-2ce4-4e3c-b16c-21a1d49abed3</tt></nobr></td>
<td><nobr><i>Root Partition (32-bit ARM)</i></bobr></td>
</tr>

<tr>
<td><nobr><tt>b921b045-1df0-41c3-af44-4c6f280d3fae</tt></nobr></td>
<td><nobr><i>Root Partition (64-bit ARM/AArch64)</i></bobr></td>
</tr>

<tr>
<td><nobr><tt>993d8d3d-f80e-4225-855a-9daf8ed7ea97</tt></nobr></td>
<td><nobr><i>Root Partition (Itanium/IA-64)</i></bobr></td>
</tr>

<tr>
<td><nobr><tt>d13c5d3b-b5d1-422a-b29f-9454fdc89d76</tt></nobr></td>
<td><nobr><i>Root Verity Partition (x86)</i></nobr></td>
<td rowspan="5">A dm-verity superblock followed by hash data</td>
<td rowspan="5">On systems with matching architecture, contains dm-verity
integrity hash data for the matching root partition. If this feature is used
the partition UUID of the root partition should be the first 128bit of the root
hash of the dm-verity hash data, and the partition UUID of this dm-verity
partition should be the final 128bit of it, so that the root partition and its
verity partition can be discovered easily, simply by specifying the root
hash.</td>
</tr>


<tr>
<td><nobr><tt>2c7357ed-ebd2-46d9-aec1-23d437ec2bf5</tt></nobr></td>
<td><nobr><i>Root Verity Partition (x86-64)</i></bobr></td>
</tr>

<tr>
<td><nobr><tt>7386cdf2-203c-47a9-a498-f2ecce45a2d6</tt></nobr></td>
<td><nobr><i>Root Verity Partition (32-bit ARM)</i></bobr></td>
</tr>

<tr>
<td><nobr><tt>df3300ce-d69f-4c92-978c-9bfb0f38d820</tt></nobr></td>
<td><nobr><i>Root Verity Partition (64-bit ARM/AArch64)</i></bobr></td>
</tr>

<tr>
<td><nobr><tt>86ed10d5-b607-45bb-8957-d350f23d0571</tt></nobr></td>
<td><nobr><i>Root Verity Partition (Itanium/IA-64)</i></bobr></td>
</tr>

<tr>
<td><nobr><tt>933ac7e1-2eb4-4f13-b844-0e14e2aef915</tt></nobr></td>
<td><nobr><i>Home Partition</i></nobr></td>
<td>Any native, optionally in LUKS</td>
<td>The first partition with this type UUID on the disk containing the root
partition is automatically mounted to <tt>/home/</tt>.  If the partition is encrypted
with LUKS, the device mapper file will be named <tt>/dev/mapper/home</tt>.</td>
</tr>

<tr>
<td><nobr><tt>3b8f8425-20e0-4f3b-907f-1a25a76f98e8</tt></nobr></td>
<td><nobr><i>Server Data Partition</i></nobr></td>
<td>Any native, optionally in LUKS</td>
<td>The first partition with this type UUID on the disk containing the root
partition is automatically mounted to <tt>/srv/</tt>.  If the partition is encrypted
with LUKS, the device mapper file will be named <tt>/dev/mapper/srv</tt>.</td>
</tr>

<tr>
<td><nobr><tt>4d21b016-b534-45c2-a9fb-5c16e091fd2d</tt></nobr></td>
<td><nobr><i>Variable Data Partition</i></nobr></td>
<td>Any native, optionally in LUKS</td>
<td>The first partition with this type UUID on the disk containing the root
partition is automatically mounted to <tt>/var/</tt> — under the condition that
its partition UUID matches the first 128 bit of <tt>HMAC-SHA256(machine-id,
0x4d21b016b53445c2a9fb5c16e091fd2d)</tt> (i.e. the SHA256 HMAC hash of the
binary type UUID keyed by the machine ID as read from <a
href="https://www.freedesktop.org/software/systemd/man/machine-id.html"><tt>/etc/machine-id</tt></a>. This
special requirement is made because <tt>/var/</tt> (unlike the other partition
types listed here) is inherently private to a specific installation and cannot
possibly be shared between multiple OS installations on the same disk, and thus
should be bound to a specific instance of the OS, identified by its machine ID.
If the partition is encrypted with LUKS, the device mapper file will be named
<tt>/dev/mapper/var</tt>.</td>
</tr>

<tr>
<td><nobr><tt>7ec6f557-3bc5-4aca-b293-16ef5df639d1</tt></nobr></td>
<td><nobr><i>Temporary Data Partition</i></nobr></td>
<td>Any native, optionally in LUKS</td>
<td>The first partition with this type UUID on the disk containing the root
partition is automatically mounted to <tt>/var/tmp/</tt>.  If the partition is
encrypted with LUKS, the device mapper file will be named
<tt>/dev/mapper/tmp</tt>. Note that the intended mount point is indeed
<tt>/var/tmp/</tt>, not <tt>/tmp/</tt>. The latter is typically maintained in
memory via <tt>tmpfs</tt> and does not require a partition on disk. In some
cases it might be desirable to make <tt>/tmp/</tt> persistent too, in which
case it is recommended to make it a symlink or bind mount to
<tt>/var/tmp/</tt>, thus not requiring its own partition type UUID.</td>
</tr>

<tr>
<td><nobr><tt>0657fd6d-a4ab-43c4-84e5-0933c84b4f4f</tt></nobr></td>
<td><nobr><i>Swap</i></nobr></td>
<td>Swap</td>
<td>All swap partitions on the disk containing the root partition are automatically enabled.</td>
</tr>

<tr>
<td><nobr><tt>c12a7328-f81f-11d2-ba4b-00a0c93ec93b</tt></nobr></td>
<td><nobr><i>EFI System Partition</i></nobr></td>
<td>VFAT</td>
<td>The ESP used for the current boot is automatically mounted to
<tt>/efi/</tt> (or <tt>/boot/</tt> as fallback), unless a different partition
is mounted there (possibly via <tt>/etc/fstab</tt>, or because the Extended
Boot Loader Partition — see below — exists) or the directory is non-empty on
the root disk.  This partition type is defined by the <a
href="http://www.uefi.org/specifications">UEFI Specification</a>.</td>
</tr>

<tr>
<td><nobr><tt>bc13c2ff-59e6-4262-a352-b275fd6f7172</tt></nobr></td>
<td><nobr><i>Extended Boot Loader Partition</i></nobr></td>
<td>Typically VFAT</td>
<td>The Extended Boot Loader Partition (XBOOTLDR) used for the current boot is
automatically mounted to <tt>/boot/</tt>, unless a different partition is
mounted there (possibly via <tt>/etc/fstab</tt>) or the directory is non-empty
on the root disk. This partition type is defined by the <a
href="https://systemd.io/BOOT_LOADER_SPECIFICATION/">Boot Loader
Specification</a>.</td> </tr>

<tr>
<td><nobr><tt>0fc63daf-8483-4772-8e79-3d69d8477de4</tt></nobr></td>
<td><nobr><i>Other Data Partitions</i></nobr></td>
<td>Any native, optionally in LUKS</td>
<td>No automatic mounting takes place for other Linux data partitions. This
partition type should be used for all partitions that carry Linux file
systems. The installer needs to mount them explicitly via entries in
<tt>/etc/fstab</tt>. Optionally, these partitions may be encrypted with LUKS.</td>
</tr>

</table>

Other GPT type IDs might be used on Linux, for example to mark software RAID or
LVM partitions. The definitions of those GPT types is outside of the scope of
this specification.

## Partition Names

For partitions of the types listed above it is recommended to use
human-friendly, descriptive partition names in the GPT partition table, for
example "*Home*", "*Server* *Data*", "*Fedora* *Root*" and similar, possibly
localized.

## Partition Flags

For the root, server data, home, variable data, temporary data and swap
partitions, the partition flag bit 63 ("*no-auto*") may be used to turn off
auto-discovery for the specific partition.  If set, the partition will not be
automatically mounted or enabled.

For the root, server data, home, variable data and temporary data partitions,
the partition flag bit 60 ("*read-only*") may be used to mark a partition for
read-only mounts only.  If set, the partition will be mounted read-only instead
of read-write. Note that the variable data partition and the temporary data
partition will generally not be able to serve their purpose if marked
read-only, since by their very definition they are supposed to be mutable. (The
home and server data partitions are generally assumed to be mutable as well,
but the requirement for them is not equally strong.) Because of that, while the
read-only flag is defined and supported, it's almost never a good idea to
actually use it for these partitions.

Note that these two flag definitions happen to map nicely to the ones used by
Microsoft Basic Data Partitions.

## Suggested Mode of Operation

An *installer* that repartitions the hard disk _should_ use the above UUID
partition types for appropriate partitions it creates.

An *installer* which supports a "manual partitioning" interface _may_ choose to
pre-populate the interface with swap, `/home/`, `/srv/`, `/var/tmp/` partitions
of pre-existing Linux installations, identified with the GPT type UUIDs
above. The installer should not pre-populate such an interface with any
identified root or `/var/` partition unless the intention is to overwrite an
existing operating system that might be installed.

An *installer* _may_ omit creating entries in `/etc/fstab` for root, `/home/`,
`/srv/`, `/var/`, `/var/tmp` and for the swap partitions if they use these UUID
partition types, and are the first partitions on the disk of each type. If the
ESP shall be mounted to `/efi/` (or `/boot/`), it may additionally omit
creating the entry for it in `/etc/fstab`.  If an extended boot partition is
used, or if the EFI partition shall not be mounted to `/efi/` or `/boot/`, it
_must_ create `/etc/fstab` entries for them.  If other partitions are used (for
example for `/usr/` or `/var/lib/mysql/`), the installer _must_ register these
in `/etc/fstab`.  The `root=` parameter passed to the kernel by the boot loader
may be omitted if the root partition is the first one on the disk of its type.
If the root partition is not the first one on the disk, the `root=` parameter
_must_ be passed to the kernel by the boot loader.  An installer that mounts a
root, `/home/`, `/srv/`, `/var/`, or `/var/tmp/` file system with the partition
types defined as above which contains a LUKS header _must_ call the device
mapper device "root", "home", "srv", "var" or "tmp", respectively.  This is
necessary to ensure that the automatic discovery will never result in different
device mapper names than any static configuration by the installer, thus
eliminating possible naming conflicts and ambiguities.

An *operating* *system* _should_ automatically discover and mount the first
root partition that does not have the no-auto flag set (as described above) by
scanning the disk containing the currently used EFI ESP.  It _should_
automatically discover and mount the first `/home/`, `/srv/`, `/var/`,
`/var/tmp/` and swap partitions that do not have the no-auto flag set by
scanning the disk containing the discovered root partition.  It should
automatically discover and mount the partition containing the currently used
EFI ESP to `/efi/` (or `/boot/` as fallback).  It should automatically discover
and mount the partition containing the currently used Extended Boot Loader
Partition to `/boot/`. It _should not_ discover or automatically mount
partitions with other UUID partition types, or partitions located on other
disks, or partitions with the no-auto flag set.  User configuration shall
always override automatic discovery and mounting.  If a root, `/home/`,
`/srv/`, `/boot/`, `/var/`, `/var/tmp/`, `/efi/`, `/boot/` or swap partition is
listed in `/etc/fstab` or with `root=` on the kernel command line, it _must_
take precedence over automatically discovered partitions.  If a `/home/`,
`/srv/`, `/boot/`, `/var/`, `/var/tmp/`, `/efi/` or `/boot/` directory is found
to be populated already in the root partition, the automatic discovery _must
not_ mount any discovered file system over it.

A *container* *manager* should automatically discover and mount the root,
`/home/`, `/srv/`, `/var/`, `/var/tmp/` partitions inside a container disk
image.  It may choose to mount any discovered ESP and/or XBOOOTLDR partition to
`/efi/` or `/boot/`. It should ignore any swap should they be included in a
container disk image.

If a btrfs file system is automatically discovered and mounted by the operating
system/container manager it will be mounted with its *default* subvolume.  The
installer should make sure to set the default subvolume correctly using "btrfs
subvolume set-default".

## Sharing of File Systems between Installations

If two Linux-based operating systems are installed on the same disk, the scheme
above suggests that they may share the swap, `/home/`, `/srv/`, `/var/tmp/`,
ESP, XBOOTLDR. However, they should each have their own root and `/var/`
partition.

## Frequently Asked Questions

### Why are you taking my `/etc/fstab` away?

We are not. `/etc/fstab` always overrides automatic discovery and is indeed
mentioned in the specifications.  We are simply trying to make the boot and
installation processes of Linux a bit more robust and self-descriptive.

### Why did you only define the root partition for x86, x86-64, ARM, ARM64, ia64?

The automatic discovery of the root partition is defined to operate on the disk
containing the current EFI System Partition (ESP). Since EFI only exists on
x86, x86-64, ia64, and ARM so far, we only defined root partition UUIDs for
these architectures.  Should EFI become more common on other architectures, we
can define additional UUIDs for them.

### Why define distinct root partition UUIDs for the various architectures?

This allows disk images that may be booted on multiple architectures to use
discovery of the appropriate root partition on each architecture.

### Doesn't this break multi-boot scenarios?

No, it doesn't.  The specification says that installers may not stop creating
`/etc/fstab` or stop including `root=` on the kernel command line, unless the used
partitions are the first ones of their type on the disk. Additionally,
`/etc/fstab` and `root=` both override automatic discovery.  Multi-boot is hence
well supported, since it doesn't change anything for anything but the first
installation.

That all said, it's not expected that generic installers generally stop setting
`root=` and creating `/etc/fstab` anyway. The option to drop these configuration
bits is primarily something for appliance-like devices.  However, generic
installers should *still* set the right GPT partition types for the partitions
they create so that container managers, partition tools and administrators can
benefit.  Phrased differently, this specification introduces A) the
*recommendation* to use the newly defined partition types to tag things
properly and B) the *option* to then drop `root=` and `/etc/fstab`.  While we
advertise A) to *all* installers, we only propose B) for simpler,
appliance-like installations.

### What partitioning tools will create a DPS-compliant partition table?

As of util-linux 2.25.2, the fdisk tool provides type codes to create the root,
home, and swap partitions that the DPS expects, but the gdisk tool (version
0.8.10) and its variants do not support creation of a root file system with a
matching type code.  By default, fdisk will create an old-style MBR, not a GPT,
so typing 'l' to list partition types will not show the choices that the root
partition with the correct UUID.  You must first create an empty GPT and then
type 'l' in order for the DPS-compliant type codes to be available.
