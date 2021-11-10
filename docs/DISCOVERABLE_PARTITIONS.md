---
title: Discoverable Partitions Specification
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---
# The Discoverable Partitions Specification (DPS)

_TL;DR: Let's automatically discover, mount and enable the root partition,
`/home/`, `/srv/`, `/var/` and `/var/tmp/` and the swap partitions based on
GUID Partition Tables (GPT)!_

This specification describes the use of GUID Partition Table (GPT) UUIDs to
enable automatic discovery of partitions and their intended mountpoints.
Traditionally Linux has made little use of partition types, mostly just
defining one UUID for file system/data partitions and another one for swap
partitions. With this specification, we introduce additional partition types
for specific uses. This has many benefits:

* OS installers can automatically discover and make sense of partitions of
  existing Linux installations.
* The OS can discover and mount the necessary file systems with a non-existent
  or incomplete `/etc/fstab` file and without the `root=` kernel command line
  option.
* Container managers (such as nspawn and libvirt-lxc) can introspect and set up
  file systems contained in GPT disk images automatically and mount them to the
  right places, thus allowing booting the same, identical images on bare metal
  and in Linux containers. This enables true, natural portability of disk
  images between physical machines and Linux containers.
* As a help to administrators and users partition manager tools can show more
  descriptive information about partitions tables.

Note that the OS side of this specification is currently implemented in
[systemd](http://systemd.io/) 211 and newer in the
[systemd-gpt-auto-generator(8)](http://www.freedesktop.org/software/systemd/man/systemd-gpt-auto-generator.html)
generator tool. Note that automatic discovery of the root only works if the
boot loader communicates this information to the OS, by implementing the [Boot
Loader
Interface](https://systemd.io/BOOT_LOADER_INTERFACE).

## Defined Partition Type UUIDs

| Partition Type UUID | Name | Allowed File Systems | Explanation |
|---------------------|------|----------------------|-------------|
| `44479540-f297-41b2-9af7-d131d5f0458a` | _Root Partition (x86)_ | Any native, optionally in LUKS | On systems with matching architecture, the first partition with this type UUID on the disk containing the active EFI ESP is automatically mounted to the root directory <tt>/</tt>. If the partition is encrypted with LUKS or has dm-verity integrity data (see below), the device mapper file will be named `/dev/mapper/root`. |
| `4f68bce3-e8cd-4db1-96e7-fbcaf984b709` | _Root Partition (x86-64)_ | ditto | ditto |
| `69dad710-2ce4-4e3c-b16c-21a1d49abed3` | _Root Partition (32-bit ARM)_ | ditto | ditto |
| `b921b045-1df0-41c3-af44-4c6f280d3fae` | _Root Partition (64-bit ARM/AArch64)_ | ditto | ditto |
| `993d8d3d-f80e-4225-855a-9daf8ed7ea97` | _Root Partition (Itanium/IA-64)_ | ditto | ditto |
| `77055800-792c-4f94-b39a-98c91b762bb6` | _Root Partition (LoongArch 64-bit)_ | ditto | ditto |
| `60d5a7fe-8e7d-435c-b714-3dd8162144e1` | _Root Partition (RISC-V 32-bit)_ | ditto | ditto |
| `72ec70a6-cf74-40e6-bd49-4bda08e8f224` | _Root Partition (RISC-V 64-bit)_ | ditto | ditto |
| `d13c5d3b-b5d1-422a-b29f-9454fdc89d76` | _Root Verity Partition (x86)_ | A dm-verity superblock followed by hash data | Contains dm-verity integrity hash data for the matching root partition. If this feature is used the partition UUID of the root partition should be the first 128 bits of the root hash of the dm-verity hash data, and the partition UUID of this dm-verity partition should be the final 128 bits of it, so that the root partition and its Verity partition can be discovered easily, simply by specifying the root hash. |
| `2c7357ed-ebd2-46d9-aec1-23d437ec2bf5` | _Root Verity Partition (x86-64)_ | ditto | ditto |
| `7386cdf2-203c-47a9-a498-f2ecce45a2d6` | _Root Verity Partition (32-bit ARM)_ | ditto | ditto |
| `df3300ce-d69f-4c92-978c-9bfb0f38d820` | _Root Verity Partition (64-bit ARM/AArch64)_ | ditto | ditto |
| `86ed10d5-b607-45bb-8957-d350f23d0571` | _Root Verity Partition (Itanium/IA-64)_  | ditto | ditto |
| `f3393b22-e9af-4613-a948-9d3bfbd0c535` | _Root Verity Partition (LoongArch 64-bit)_  | ditto | ditto |
| `ae0253be-1167-4007-ac68-43926c14c5de` | _Root Verity Partition (RISC-V 32-bit)_  | ditto | ditto |
| `b6ed5582-440b-4209-b8da-5ff7c419ea3d` | _Root Verity Partition (RISC-V 64-bit)_  | ditto | ditto |
| `5996fc05-109c-48de-808b-23fa0830b676` | _Root Verity Signature Partition (x86)_ | A serialized JSON object, see below | Contains a root hash and a PKCS#7 signature for it, permitting signed dm-verity GPT images |
| `41092b05-9fc8-4523-994f-2def0408b176` | _Root Verity Signature Partition (x86-64)_ | ditto | ditto |
| `42b0455f-eb11-491d-98d3-56145ba9d037` | _Root Verity Signature Partition (32-bit ARM)_ | ditto | ditto |
| `6db69de6-29f4-4758-a7a5-962190f00ce3` | _Root Verity Signature Partition (64-bit ARM/AArch64)_ | ditto | ditto |
| `e98b36ee-32ba-4882-9b12-0ce14655f46a` | _Root Verity Signature Partition (Itanium/IA-64)_  | ditto | ditto |
| `5afb67eb-ecc8-4f85-ae8e-ac1e7c50e7d0` | _Root Verity Signature Partition (LoongArch 64-bit)_  | ditto | ditto |
| `3a112a75-8729-4380-b4cf-764d79934448` | _Root Verity Signature Partition (RISC-V 32-bit)_  | ditto | ditto |
| `efe0f087-ea8d-4469-821a-4c2a96a8386a` | _Root Verity Signature Partition (RISC-V 64-bit)_  | ditto | ditto |
| `75250d76-8cc6-458e-bd66-bd47cc81a812` | _`/usr/` Partition (x86)_ | Any native, optionally in LUKS | Similar semantics to root partition, but just the `/usr/` partition. |
| `8484680c-9521-48c6-9c11-b0720656f69e` | _`/usr/` Partition (x86-64)_ | ditto | ditto |
| `7d0359a3-02b3-4f0a-865c-654403e70625` | _`/usr/` Partition (32-bit ARM)_ | ditto | ditto |
| `b0e01050-ee5f-4390-949a-9101b17104e9` | _`/usr/` Partition (64-bit ARM/AArch64)_ | ditto | ditto |
| `4301d2a6-4e3b-4b2a-bb94-9e0b2c4225ea` | _`/usr/` Partition (Itanium/IA-64)_ | ditto | ditto |
| `e611c702-575c-4cbe-9a46-434fa0bf7e3f` | _`/usr/` Partition (LoongArch 64-bit)_ | ditto | ditto |
| `b933fb22-5c3f-4f91-af90-e2bb0fa50702` | _`/usr/` Partition (RISC-V 32-bit)_ | ditto | ditto |
| `beaec34b-8442-439b-a40b-984381ed097d` | _`/usr/` Partition (RISC-V 64-bit)_ | ditto | ditto |
| `8f461b0d-14ee-4e81-9aa9-049b6fb97abd` | _`/usr/` Verity Partition (x86)_ | A dm-verity superblock followed by hash data | Similar semantics to root Verity partition, but just for the `/usr/` partition. |
| `77ff5f63-e7b6-4633-acf4-1565b864c0e6` | _`/usr/` Verity Partition (x86-64)_ | ditto | ditto |
| `c215d751-7bcd-4649-be90-6627490a4c05` | _`/usr/` Verity Partition (32-bit ARM)_ | ditto | ditto |
| `6e11a4e7-fbca-4ded-b9e9-e1a512bb664e` | _`/usr/` Verity Partition (64-bit ARM/AArch64)_ | ditto | ditto |
| `6a491e03-3be7-4545-8e38-83320e0ea880` | _`/usr/` Verity Partition (Itanium/IA-64)_ | ditto | ditto |
| `f46b2c26-59ae-48f0-9106-c50ed47f673d` | _`/usr/` Verity Partition (LoongArch 64-bit)_ | ditto | ditto |
| `cb1ee4e3-8cd0-4136-a0a4-aa61a32e8730` | _`/usr/` Verity Partition (RISC-V 32-bit)_ | ditto | ditto |
| `8f1056be-9b05-47c4-81d6-be53128e5b54` | _`/usr/` Verity Partition (RISC-V 64-bit)_ | ditto | ditto |
| `974a71c0-de41-43c3-be5d-5c5ccd1ad2c0` | _`/usr/` Verity Signature Partition (x86)_ | A serialized JSON object, see below | Similar semantics to root Verity signature partition, but just for the `/usr/` partition. |
| `e7bb33fb-06cf-4e81-8273-e543b413e2e2` | _`/usr/` Verity Signature Partition (x86-64)_ | ditto | ditto |
| `d7ff812f-37d1-4902-a810-d76ba57b975a` | _`/usr/` Verity Signature Partition (32-bit ARM)_ | ditto | ditto |
| `c23ce4ff-44bd-4b00-b2d4-b41b3419e02a` | _`/usr/` Verity Signature Partition (64-bit ARM/AArch64)_ | ditto | ditto |
| `8de58bc2-2a43-460d-b14e-a76e4a17b47f` | _`/usr/` Verity Signature Partition (Itanium/IA-64)_ | ditto | ditto |
| `b024f315-d330-444c-8461-44bbde524e99` | _`/usr/` Verity Signature Partition (LoongArch 64-bit)_ | ditto | ditto |
| `c3836a13-3137-45ba-b583-b16c50fe5eb4` | _`/usr/` Verity Signature Partition (RISC-V 32-bit)_ | ditto | ditto |
| `d2f9000a-7a18-453f-b5cd-4d32f77a7b32` | _`/usr/` Verity Signature Partition (RISC-V 64-bit)_ | ditto | ditto |
| `933ac7e1-2eb4-4f13-b844-0e14e2aef915` | _Home Partition_ | Any native, optionally in LUKS | The first partition with this type UUID on the disk containing the root partition is automatically mounted to `/home/`.  If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/home`. |
| `3b8f8425-20e0-4f3b-907f-1a25a76f98e8` | _Server Data Partition_ | Any native, optionally in LUKS | The first partition with this type UUID on the disk containing the root partition is automatically mounted to `/srv/`.  If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/srv`. |
| `4d21b016-b534-45c2-a9fb-5c16e091fd2d` | _Variable Data Partition_ | Any native, optionally in LUKS | The first partition with this type UUID on the disk containing the root partition is automatically mounted to `/var/` — under the condition that its partition UUID matches the first 128 bits of `HMAC-SHA256(machine-id, 0x4d21b016b53445c2a9fb5c16e091fd2d)` (i.e. the SHA256 HMAC hash of the binary type UUID keyed by the machine ID as read from [`/etc/machine-id`](https://www.freedesktop.org/software/systemd/man/machine-id.html). This special requirement is made because `/var/` (unlike the other partition types listed here) is inherently private to a specific installation and cannot possibly be shared between multiple OS installations on the same disk, and thus should be bound to a specific instance of the OS, identified by its machine ID. If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/var`. |
| `7ec6f557-3bc5-4aca-b293-16ef5df639d1` | _Temporary Data Partition_ | Any native, optionally in LUKS | The first partition with this type UUID on the disk containing the root partition is automatically mounted to `/var/tmp/`.  If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/tmp`. Note that the intended mount point is indeed `/var/tmp/`, not `/tmp/`. The latter is typically maintained in memory via <tt>tmpfs</tt> and does not require a partition on disk. In some cases it might be desirable to make `/tmp/` persistent too, in which case it is recommended to make it a symlink or bind mount to `/var/tmp/`, thus not requiring its own partition type UUID. |
| `0657fd6d-a4ab-43c4-84e5-0933c84b4f4f` | _Swap_ | Swap, optionally in LUKS | All swap partitions on the disk containing the root partition are automatically enabled. If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/swap`. This partition type predates the Discoverable Partitions Specification. |
| `0fc63daf-8483-4772-8e79-3d69d8477de4` | _Generic Linux Data Partitions_ | Any native, optionally in LUKS | No automatic mounting takes place for other Linux data partitions. This partition type should be used for all partitions that carry Linux file systems. The installer needs to mount them explicitly via entries in <tt>/etc/fstab</tt>. Optionally, these partitions may be encrypted with LUKS. This partition type predates the Discoverable Partitions Specification. |
| `c12a7328-f81f-11d2-ba4b-00a0c93ec93b` | _EFI System Partition_ | VFAT | The ESP used for the current boot is automatically mounted to `/efi/` (or `/boot/` as fallback), unless a different partition is mounted there (possibly via `/etc/fstab`, or because the Extended Boot Loader Partition — see below — exists) or the directory is non-empty on the root disk.  This partition type is defined by the [UEFI Specification](http://www.uefi.org/specifications). |
| `bc13c2ff-59e6-4262-a352-b275fd6f7172` | _Extended Boot Loader Partition_ | Typically VFAT | The Extended Boot Loader Partition (XBOOTLDR) used for the current boot is automatically mounted to <tt>/boot/</tt>, unless a different partition is mounted there (possibly via <tt>/etc/fstab</tt>) or the directory is non-empty on the root disk. This partition type is defined by the [Boot Loader Specification](https://systemd.io/BOOT_LOADER_SPECIFICATION). |

Other GPT type IDs might be used on Linux, for example to mark software RAID or
LVM partitions. The definitions of those GPT types is outside of the scope of
this specification.

[systemd-id128(1)](http://www.freedesktop.org/software/systemd/man/systemd-id128.html)'s
`show` command may be used to list those GPT partition type UUIDs.

## Partition Names

For partitions of the types listed above it is recommended to use
human-friendly, descriptive partition names in the GPT partition table, for
example "*Home*", "*Server* *Data*", "*Fedora* *Root*" and similar, possibly
localized.

For the Root/Verity/Verity signature partitions it might make sense to use a
versioned naming scheme reflecting the OS name and its version,
e.g. "fooOS_2021.4" or similar.

## Partition Flags

This specification defines three GPT partition flags that may be set for the
partition types defined above:

1. For the root, `/usr/`, Verity, Verity signature, home, server data, variable
   data, temporary data, swap and extended boot loader partitions, the
   partition flag bit 63 ("*no-auto*") may be used to turn off auto-discovery
   for the specific partition.  If set, the partition will not be automatically
   mounted or enabled.

2. For the root, `/usr/`, Verity, Verity signature home, server data, variable
   data, temporary data and extended boot loader partitions, the partition flag
   bit 60 ("*read-only*") may be used to mark a partition for read-only mounts
   only.  If set, the partition will be mounted read-only instead of
   read-write. Note that the variable data partition and the temporary data
   partition will generally not be able to serve their purpose if marked
   read-only, since by their very definition they are supposed to be
   mutable. (The home and server data partitions are generally assumed to be
   mutable as well, but the requirement for them is not equally strong.)
   Because of that, while the read-only flag is defined and supported, it's
   almost never a good idea to actually use it for these partitions. Also note
   that Verity and signature partitions are by their semantics always
   read-only. The flag is hence of little effect for them, and it is
   recommended to set it unconditionally for the Verity and signature partition
   types.

3. For the root, `/usr/`, home, server data, variable data, temporary data and
   extended boot loader partitions, the partition flag bit 59
   ("*grow-file-system*") may be used to mark a partition for automatic growing
   of the contained file system to the size of the partition when
   mounted. Tools that automatically mount disk image with a GPT partition
   table are suggested to implicitly grow the contained file system to the
   partition size they are contained in, if they are found to be smaller. This
   flag is without effect on partitions marked read-only.

Note that the first two flag definitions happen to correspond nicely to the
same ones used by Microsoft Basic Data Partitions.

All three of these flags generally affect only auto-discovery and automatic
mounting of disk images. If partitions marked with these flags are mounted
using low-level commands like
[mount(8)](https://man7.org/linux/man-pages/man2/mount.8.html) or directly with
[mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html), they typically
have no effect.

## Verity

The Root/`/usr/` partition types and their matching Verity and Verity signature
partitions enable relatively automatic handling of `dm-verity` protected
setups. These types are defined with two modes of operation in mind:

1. A trusted Verity root hash is passed in externally, for example is specified
   on the kernel command line that is signed along with the kernel image using
   SecureBoot PE signing (which in turn is tested against a set of
   firmware-provided set of signing keys). If so, discovery and setup of a
   Verity volume may be fully automatic: if the root partition's UUID is chosen
   to match the first 128 bit of the root hash, and the matching Verity
   partition UUIDs is chosen to match the last 128bit of the root hash, then
   automatic discovery and match-up of the two partitions is possible, as the
   root hash is enough to both find the partitions and then combine them in a
   Verity volume. In this mode a Verity signature partition is not used and
   unnecessary.

2. A Verity signature partition is included on the disk, with a signature to be
   tested against a system-provided set of signing keys. The signature
   partition primarily contains two fields: the root hash to use, and a PKCS#7
   signature of it, using a signature key trusted by the OS. If so, discovery
   and setup of a Verity volume may be fully automatic. First, the specified
   root hash is validated with the signature and the OS-provided trusted
   keys. If the signature checks out the root hash is then used in the same way
   as in the first mode of operation described above.

Both modes of operation may be combined in a single image. This is particularly
useful for images that shall be usable in two different contexts: for example
an image that shall be able to boot directly on UEFI systems (in which
case it makes sense to include the root hash on the kernel command line that is
included in the signed kernel image to boot, as per mode of operation #1
above), but also be able to used as image for a container engine (such as
`systemd-nspawn`), which can use the signature partition to validate the image,
without making use of the signed kernel image (and thus following mode of
operation #2).

The Verity signature partition's contents should be a serialized JSON object in
text form, padded with NUL bytes to the next multiple of 4096 bytes in
size. Currently three fields are defined for the JSON object:

1. The (mandatory) `rootHash` field should be a string containing the Verity root hash,
   formatted as series of (lowercase) hex characters.

2. The (mandatory) `signature` field should be a string containing the PKCS#7
   signature of the root hash, in Base64-encoded DER format. This should be the
   same format used by the Linux kernel's dm-verity signature logic, i.e. the
   signed data should be the exact string representation of the hash, as stored
   in `rootHash` above.

3. The (optional) `certificateFingerprint` field should be a string containing
   a SHA256 fingerprint of the X.509 certificate for the key that signed the
   root hash, formatted as series of (lowercase) hex characters (no `:`
   separators or such).

More fields might be added in later revisions of this specification.

## Suggested Mode of Operation

An *installer* that repartitions the hard disk _should_ use the above UUID
partition types for appropriate partitions it creates.

An *installer* which supports a "manual partitioning" interface _may_ choose to
pre-populate the interface with swap, `/home/`, `/srv/`, `/var/tmp/` partitions
of pre-existing Linux installations, identified with the GPT type UUIDs
above. The installer should not pre-populate such an interface with any
identified root, `/usr` or `/var/` partition unless the intention is to
overwrite an existing operating system that might be installed.

An *installer* _may_ omit creating entries in `/etc/fstab` for root, `/home/`,
`/srv/`, `/var/`, `/var/tmp` and for the swap partitions if they use these UUID
partition types, and are the first partitions on the disk of each type. If the
ESP shall be mounted to `/efi/` (or `/boot/`), it may additionally omit
creating the entry for it in `/etc/fstab`.  If the EFI partition shall not be
mounted to `/efi/` or `/boot/`, it _must_ create `/etc/fstab` entries for them.
If other partitions are used (for example for `/usr/local/` or
`/var/lib/mysql/`), the installer _must_ register these in `/etc/fstab`.  The
`root=` parameter passed to the kernel by the boot loader may be omitted if the
root partition is the first one on the disk of its type.  If the root partition
is not the first one on the disk, the `root=` parameter _must_ be passed to the
kernel by the boot loader.  An installer that mounts a root, `/usr/`, `/home/`,
`/srv/`, `/var/`, or `/var/tmp/` file system with the partition types defined
as above which contains a LUKS header _must_ call the device mapper device
"root", "usr", "home", "srv", "var" or "tmp", respectively.  This is necessary
to ensure that the automatic discovery will never result in different device
mapper names than any static configuration by the installer, thus eliminating
possible naming conflicts and ambiguities.

An *operating* *system* _should_ automatically discover and mount the first
root partition that does not have the no-auto flag set (as described above) by
scanning the disk containing the currently used EFI ESP.  It _should_
automatically discover and mount the first `/usr/`, `/home/`, `/srv/`, `/var/`,
`/var/tmp/` and swap partitions that do not have the no-auto flag set by
scanning the disk containing the discovered root partition.  It should
automatically discover and mount the partition containing the currently used
EFI ESP to `/efi/` (or `/boot/` as fallback).  It should automatically discover
and mount the partition containing the currently used Extended Boot Loader
Partition to `/boot/`. It _should not_ discover or automatically mount
partitions with other UUID partition types, or partitions located on other
disks, or partitions with the no-auto flag set.  User configuration shall
always override automatic discovery and mounting.  If a root, `/usr/`,
`/home/`, `/srv/`, `/boot/`, `/var/`, `/var/tmp/`, `/efi/`, `/boot/` or swap
partition is listed in `/etc/fstab` or with `root=` on the kernel command line,
it _must_ take precedence over automatically discovered partitions.  If a
`/home/`, `/usr/`, `/srv/`, `/boot/`, `/var/`, `/var/tmp/`, `/efi/` or `/boot/`
directory is found to be populated already in the root partition, the automatic
discovery _must not_ mount any discovered file system over it. Optionally, in
case of the root, `/usr/` and their Verity partitions instead of strictly
mounting the first suitable partition an OS might choose to mount the partition
whose label compares the highest according to `strverscmp()` or a similar
logic, in order to implement a simple partition-based A/B versioning
scheme. The precise rules are left for the implementation to decide, but when
in doubt earlier partitions (by their index) should always win over later
partitions if the label comparison is inconclusive.

A *container* *manager* should automatically discover and mount the root,
`/usr/`, `/home/`, `/srv/`, `/var/`, `/var/tmp/` partitions inside a container
disk image.  It may choose to mount any discovered ESP and/or XBOOOTLDR
partition to `/efi/` or `/boot/`. It should ignore any swap should they be
included in a container disk image.

If a btrfs file system is automatically discovered and mounted by the operating
system/container manager it will be mounted with its *default* subvolume.  The
installer should make sure to set the default subvolume correctly using "btrfs
subvolume set-default".

## Sharing of File Systems between Installations

If two Linux-based operating systems are installed on the same disk, the scheme
above suggests that they may share the swap, `/home/`, `/srv/`, `/var/tmp/`,
ESP, XBOOTLDR. However, they should each have their own root, `/usr/` and
`/var/` partition.

## Frequently Asked Questions

### Why are you taking my `/etc/fstab` away?

We are not. `/etc/fstab` always overrides automatic discovery and is indeed
mentioned in the specifications.  We are simply trying to make the boot and
installation processes of Linux a bit more robust and self-descriptive.

### Why did you only define the root partition for these listed architectures?

Please submit a patch that adds appropriate partition type UUIDs for the
architecture of your choice should they be missing so far. The only reason they
aren't defined yet is that nobody submitted them yet.

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

As of util-linux 2.25.2, the `fdisk` tool provides type codes to create the
root, home, and swap partitions that the DPS expects. By default, `fdisk` will
create an old-style MBR, not a GPT, so typing `l` to list partition types will
not show the choices to let you set the correct UUID. Make sure to first create
an empty GPT, then type `l` in order for the DPS-compliant type codes to be
available.

The `gdisk` tool (from version 1.0.5 onward) and its variants (`sgdisk`,
`cgdisk`) also support creation of partitions with a matching type code.
