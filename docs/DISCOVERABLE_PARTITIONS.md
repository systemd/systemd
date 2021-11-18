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

<!-- generated with tools/list-discoverable-partitions.py -->
| Partition Type UUID | Name | Allowed File Systems | Explanation |
|---------------------|------|----------------------|-------------|
| _Root Partition (Alpha)_ | `6523f8ae-3eb1-4e2a-a05a-18b695ae656f` | Any native, optionally in LUKS | On systems with matching architecture, the first partition with this type UUID on the disk containing the active EFI ESP is automatically mounted to the root directory <tt>/</tt>. If the partition is encrypted with LUKS or has dm-verity integrity data (see below), the device mapper file will be named `/dev/mapper/root`. |
| _Root Partition (ARC)_ | `d27f46ed-2919-4cb8-bd25-9531f3c16534` | ditto | ditto |
| _Root Partition (32-bit ARM)_ | `69dad710-2ce4-4e3c-b16c-21a1d49abed3` | ditto | ditto |
| _Root Partition (64-bit ARM/AArch64)_ | `b921b045-1df0-41c3-af44-4c6f280d3fae` | ditto | ditto |
| _Root Partition (Itanium/IA-64)_ | `993d8d3d-f80e-4225-855a-9daf8ed7ea97` | ditto | ditto |
| _Root Partition (LoongArch 64-bit)_ | `77055800-792c-4f94-b39a-98c91b762bb6` | ditto | ditto |
| _Root Partition (32-bit MIPS LittleEndian (mipsel))_ | `37c58c8a-d913-4156-a25f-48b1b64e07f0` | ditto | ditto |
| _Root Partition (64-bit MIPS LittleEndian (mips64el))_ | `700bda43-7a34-4507-b179-eeb93d7a7ca3` | ditto | ditto |
| _Root Partition (32-bit PowerPC)_ | `1de3f1ef-fa98-47b5-8dcd-4a860a654d78` | ditto | ditto |
| _Root Partition (64-bit PowerPC BigEndian)_ | `912ade1d-a839-4913-8964-a10eee08fbd2` | ditto | ditto |
| _Root Partition (64-bit PowerPC LittleEndian)_ | `c31c45e6-3f39-412e-80fb-4809c4980599` | ditto | ditto |
| _Root Partition (RISC-V 32-bit)_ | `60d5a7fe-8e7d-435c-b714-3dd8162144e1` | ditto | ditto |
| _Root Partition (RISC-V 64-bit)_ | `72ec70a6-cf74-40e6-bd49-4bda08e8f224` | ditto | ditto |
| _Root Partition (s390)_ | `08a7acea-624c-4a20-91e8-6e0fa67d23f9` | ditto | ditto |
| _Root Partition (s390x)_ | `5eead9a9-fe09-4a1e-a1d7-520d00531306` | ditto | ditto |
| _Root Partition (TILE-Gx)_ | `c50cdd70-3862-4cc3-90e1-809a8c93ee2c` | ditto | ditto |
| _Root Partition (x86)_ | `44479540-f297-41b2-9af7-d131d5f0458a` | ditto | ditto |
| _Root Partition (amd64/x86_64)_ | `4f68bce3-e8cd-4db1-96e7-fbcaf984b709` | ditto | ditto |
| _`/usr/` Partition (Alpha)_ | `e18cf08c-33ec-4c0d-8246-c6c6fb3da024` | A dm-verity superblock followed by hash data | Contains dm-verity integrity hash data for the matching root partition. If this feature is used the partition UUID of the root partition should be the first 128 bits of the root hash of the dm-verity hash data, and the partition UUID of this dm-verity partition should be the final 128 bits of it, so that the root partition and its Verity partition can be discovered easily, simply by specifying the root hash. |
| _`/usr/` Partition (ARC)_ | `7978a683-6316-4922-bbee-38bff5a2fecc` | ditto | ditto |
| _`/usr/` Partition (32-bit ARM)_ | `7d0359a3-02b3-4f0a-865c-654403e70625` | ditto | ditto |
| _`/usr/` Partition (64-bit ARM/AArch64)_ | `b0e01050-ee5f-4390-949a-9101b17104e9` | ditto | ditto |
| _`/usr/` Partition (Itanium/IA-64)_ | `4301d2a6-4e3b-4b2a-bb94-9e0b2c4225ea` | ditto | ditto |
| _`/usr/` Partition (LoongArch 64-bit)_ | `e611c702-575c-4cbe-9a46-434fa0bf7e3f` | ditto | ditto |
| _`/usr/` Partition (32-bit MIPS LittleEndian (mipsel))_ | `0f4868e9-9952-4706-979f-3ed3a473e947` | ditto | ditto |
| _`/usr/` Partition (64-bit MIPS LittleEndian (mips64el))_ | `c97c1f32-ba06-40b4-9f22-236061b08aa8` | ditto | ditto |
| _`/usr/` Partition (32-bit PowerPC)_ | `7d14fec5-cc71-415d-9d6c-06bf0b3c3eaf` | ditto | ditto |
| _`/usr/` Partition (64-bit PowerPC BigEndian)_ | `2c9739e2-f068-46b3-9fd0-01c5a9afbcca` | ditto | ditto |
| _`/usr/` Partition (64-bit PowerPC LittleEndian)_ | `15bb03af-77e7-4d4a-b12b-c0d084f7491c` | ditto | ditto |
| _`/usr/` Partition (RISC-V 32-bit)_ | `b933fb22-5c3f-4f91-af90-e2bb0fa50702` | ditto | ditto |
| _`/usr/` Partition (RISC-V 64-bit)_ | `beaec34b-8442-439b-a40b-984381ed097d` | ditto | ditto |
| _`/usr/` Partition (s390)_ | `cd0f869b-d0fb-4ca0-b141-9ea87cc78d66` | ditto | ditto |
| _`/usr/` Partition (s390x)_ | `8a4f5770-50aa-4ed3-874a-99b710db6fea` | ditto | ditto |
| _`/usr/` Partition (TILE-Gx)_ | `55497029-c7c1-44cc-aa39-815ed1558630` | ditto | ditto |
| _`/usr/` Partition (x86)_ | `75250d76-8cc6-458e-bd66-bd47cc81a812` | ditto | ditto |
| _`/usr/` Partition (amd64/x86_64)_ | `8484680c-9521-48c6-9c11-b0720656f69e` | ditto | ditto |
| _Root Verity Partition (Alpha)_ | `fc56d9e9-e6e5-4c06-be32-e74407ce09a5` | A serialized JSON object, see below | Contains a root hash and a PKCS#7 signature for it, permitting signed dm-verity GPT images. |
| _Root Verity Partition (ARC)_ | `24b2d975-0f97-4521-afa1-cd531e421b8d` | ditto | ditto |
| _Root Verity Partition (32-bit ARM)_ | `7386cdf2-203c-47a9-a498-f2ecce45a2d6` | ditto | ditto |
| _Root Verity Partition (64-bit ARM/AArch64)_ | `df3300ce-d69f-4c92-978c-9bfb0f38d820` | ditto | ditto |
| _Root Verity Partition (Itanium/IA-64)_ | `86ed10d5-b607-45bb-8957-d350f23d0571` | ditto | ditto |
| _Root Verity Partition (LoongArch 64-bit)_ | `f3393b22-e9af-4613-a948-9d3bfbd0c535` | ditto | ditto |
| _Root Verity Partition (32-bit MIPS LittleEndian (mipsel))_ | `d7d150d2-2a04-4a33-8f12-16651205ff7b` | ditto | ditto |
| _Root Verity Partition (64-bit MIPS LittleEndian (mips64el))_ | `16b417f8-3e06-4f57-8dd2-9b5232f41aa6` | ditto | ditto |
| _Root Verity Partition (64-bit PowerPC LittleEndian)_ | `906bd944-4589-4aae-a4e4-dd983917446a` | ditto | ditto |
| _Root Verity Partition (64-bit PowerPC BigEndian)_ | `9225a9a3-3c19-4d89-b4f6-eeff88f17631` | ditto | ditto |
| _Root Verity Partition (32-bit PowerPC)_ | `98cfe649-1588-46dc-b2f0-add147424925` | ditto | ditto |
| _Root Verity Partition (RISC-V 32-bit)_ | `ae0253be-1167-4007-ac68-43926c14c5de` | ditto | ditto |
| _Root Verity Partition (RISC-V 64-bit)_ | `b6ed5582-440b-4209-b8da-5ff7c419ea3d` | ditto | ditto |
| _Root Verity Partition (s390x)_ | `b325bfbe-c7be-4ab8-8357-139e652d2f6b` | ditto | ditto |
| _Root Verity Partition (s390)_ | `7ac63b47-b25c-463b-8df8-b4a94e6c90e1` | ditto | ditto |
| _Root Verity Partition (TILE-Gx)_ | `966061ec-28e4-4b2e-b4a5-1f0a825a1d84` | ditto | ditto |
| _Root Verity Partition (amd64/x86_64)_ | `2c7357ed-ebd2-46d9-aec1-23d437ec2bf5` | ditto | ditto |
| _Root Verity Partition (x86)_ | `d13c5d3b-b5d1-422a-b29f-9454fdc89d76` | ditto | ditto |
| _`/usr/` Verity Partition (Alpha)_ | `8cce0d25-c0d0-4a44-bd87-46331bf1df67` | Any native, optionally in LUKS | Similar semantics to root partition, but just the `/usr/` partition. |
| _`/usr/` Verity Partition (ARC)_ | `fca0598c-d880-4591-8c16-4eda05c7347c` | ditto | ditto |
| _`/usr/` Verity Partition (32-bit ARM)_ | `c215d751-7bcd-4649-be90-6627490a4c05` | ditto | ditto |
| _`/usr/` Verity Partition (64-bit ARM/AArch64)_ | `6e11a4e7-fbca-4ded-b9e9-e1a512bb664e` | ditto | ditto |
| _`/usr/` Verity Partition (Itanium/IA-64)_ | `6a491e03-3be7-4545-8e38-83320e0ea880` | ditto | ditto |
| _`/usr/` Verity Partition (LoongArch 64-bit)_ | `f46b2c26-59ae-48f0-9106-c50ed47f673d` | ditto | ditto |
| _`/usr/` Verity Partition (32-bit MIPS LittleEndian (mipsel))_ | `46b98d8d-b55c-4e8f-aab3-37fca7f80752` | ditto | ditto |
| _`/usr/` Verity Partition (64-bit MIPS LittleEndian (mips64el))_ | `3c3d61fe-b5f3-414d-bb71-8739a694a4ef` | ditto | ditto |
| _`/usr/` Verity Partition (64-bit PowerPC LittleEndian)_ | `ee2b9983-21e8-4153-86d9-b6901a54d1ce` | ditto | ditto |
| _`/usr/` Verity Partition (64-bit PowerPC BigEndian)_ | `bdb528a5-a259-475f-a87d-da53fa736a07` | ditto | ditto |
| _`/usr/` Verity Partition (32-bit PowerPC)_ | `df765d00-270e-49e5-bc75-f47bb2118b09` | ditto | ditto |
| _`/usr/` Verity Partition (RISC-V 32-bit)_ | `cb1ee4e3-8cd0-4136-a0a4-aa61a32e8730` | ditto | ditto |
| _`/usr/` Verity Partition (RISC-V 64-bit)_ | `8f1056be-9b05-47c4-81d6-be53128e5b54` | ditto | ditto |
| _`/usr/` Verity Partition (s390x)_ | `31741cc4-1a2a-4111-a581-e00b447d2d06` | ditto | ditto |
| _`/usr/` Verity Partition (s390)_ | `b663c618-e7bc-4d6d-90aa-11b756bb1797` | ditto | ditto |
| _`/usr/` Verity Partition (TILE-Gx)_ | `2fb4bf56-07fa-42da-8132-6b139f2026ae` | ditto | ditto |
| _`/usr/` Verity Partition (amd64/x86_64)_ | `77ff5f63-e7b6-4633-acf4-1565b864c0e6` | ditto | ditto |
| _`/usr/` Verity Partition (x86)_ | `8f461b0d-14ee-4e81-9aa9-049b6fb97abd` | ditto | ditto |
| _Root Verity Signature Partition (Alpha)_ | `d46495b7-a053-414f-80f7-700c99921ef8` | A dm-verity superblock followed by hash data | Similar semantics to root Verity partition, but just for the `/usr/` partition. |
| _Root Verity Signature Partition (ARC)_ | `143a70ba-cbd3-4f06-919f-6c05683a78bc` | ditto | ditto |
| _Root Verity Signature Partition (32-bit ARM)_ | `42b0455f-eb11-491d-98d3-56145ba9d037` | ditto | ditto |
| _Root Verity Signature Partition (64-bit ARM/AArch64)_ | `6db69de6-29f4-4758-a7a5-962190f00ce3` | ditto | ditto |
| _Root Verity Signature Partition (Itanium/IA-64)_ | `e98b36ee-32ba-4882-9b12-0ce14655f46a` | ditto | ditto |
| _Root Verity Signature Partition (LoongArch 64-bit)_ | `5afb67eb-ecc8-4f85-ae8e-ac1e7c50e7d0` | ditto | ditto |
| _Root Verity Signature Partition (32-bit MIPS LittleEndian (mipsel))_ | `c919cc1f-4456-4eff-918c-f75e94525ca5` | ditto | ditto |
| _Root Verity Signature Partition (64-bit MIPS LittleEndian (mips64el))_ | `904e58ef-5c65-4a31-9c57-6af5fc7c5de7` | ditto | ditto |
| _Root Verity Signature Partition (64-bit PowerPC LittleEndian)_ | `d4a236e7-e873-4c07-bf1d-bf6cf7f1c3c6` | ditto | ditto |
| _Root Verity Signature Partition (64-bit PowerPC BigEndian)_ | `f5e2c20c-45b2-4ffa-bce9-2a60737e1aaf` | ditto | ditto |
| _Root Verity Signature Partition (32-bit PowerPC)_ | `1b31b5aa-add9-463a-b2ed-bd467fc857e7` | ditto | ditto |
| _Root Verity Signature Partition (RISC-V 32-bit)_ | `3a112a75-8729-4380-b4cf-764d79934448` | ditto | ditto |
| _Root Verity Signature Partition (RISC-V 64-bit)_ | `efe0f087-ea8d-4469-821a-4c2a96a8386a` | ditto | ditto |
| _Root Verity Signature Partition (s390x)_ | `c80187a5-73a3-491a-901a-017c3fa953e9` | ditto | ditto |
| _Root Verity Signature Partition (s390)_ | `3482388e-4254-435a-a241-766a065f9960` | ditto | ditto |
| _Root Verity Signature Partition (TILE-Gx)_ | `b3671439-97b0-4a53-90f7-2d5a8f3ad47b` | ditto | ditto |
| _Root Verity Signature Partition (amd64/x86_64)_ | `41092b05-9fc8-4523-994f-2def0408b176` | ditto | ditto |
| _Root Verity Signature Partition (x86)_ | `5996fc05-109c-48de-808b-23fa0830b676` | ditto | ditto |
| _`/usr/` Verity Signature Partition (Alpha)_ | `5c6e1c76-076a-457a-a0fe-f3b4cd21ce6e` | A serialized JSON object, see below | Similar semantics to root Verity signature partition, but just for the `/usr/` partition. |
| _`/usr/` Verity Signature Partition (ARC)_ | `94f9a9a1-9971-427a-a400-50cb297f0f35` | ditto | ditto |
| _`/usr/` Verity Signature Partition (32-bit ARM)_ | `d7ff812f-37d1-4902-a810-d76ba57b975a` | ditto | ditto |
| _`/usr/` Verity Signature Partition (64-bit ARM/AArch64)_ | `c23ce4ff-44bd-4b00-b2d4-b41b3419e02a` | ditto | ditto |
| _`/usr/` Verity Signature Partition (Itanium/IA-64)_ | `8de58bc2-2a43-460d-b14e-a76e4a17b47f` | ditto | ditto |
| _`/usr/` Verity Signature Partition (LoongArch 64-bit)_ | `b024f315-d330-444c-8461-44bbde524e99` | ditto | ditto |
| _`/usr/` Verity Signature Partition (32-bit MIPS LittleEndian (mipsel))_ | `3e23ca0b-a4bc-4b4e-8087-5ab6a26aa8a9` | ditto | ditto |
| _`/usr/` Verity Signature Partition (64-bit MIPS LittleEndian (mips64el))_ | `f2c2c7ee-adcc-4351-b5c6-ee9816b66e16` | ditto | ditto |
| _`/usr/` Verity Signature Partition (64-bit PowerPC LittleEndian)_ | `c8bfbd1e-268e-4521-8bba-bf314c399557` | ditto | ditto |
| _`/usr/` Verity Signature Partition (64-bit PowerPC BigEndian)_ | `0b888863-d7f8-4d9e-9766-239fce4d58af` | ditto | ditto |
| _`/usr/` Verity Signature Partition (32-bit PowerPC)_ | `7007891d-d371-4a80-86a4-5cb875b9302e` | ditto | ditto |
| _`/usr/` Verity Signature Partition (RISC-V 32-bit)_ | `c3836a13-3137-45ba-b583-b16c50fe5eb4` | ditto | ditto |
| _`/usr/` Verity Signature Partition (RISC-V 64-bit)_ | `d2f9000a-7a18-453f-b5cd-4d32f77a7b32` | ditto | ditto |
| _`/usr/` Verity Signature Partition (s390x)_ | `3f324816-667b-46ae-86ee-9b0c0c6c11b4` | ditto | ditto |
| _`/usr/` Verity Signature Partition (s390)_ | `17440e4f-a8d0-467f-a46e-3912ae6ef2c5` | ditto | ditto |
| _`/usr/` Verity Signature Partition (TILE-Gx)_ | `4ede75e2-6ccc-4cc8-b9c7-70334b087510` | ditto | ditto |
| _`/usr/` Verity Signature Partition (amd64/x86_64)_ | `e7bb33fb-06cf-4e81-8273-e543b413e2e2` | ditto | ditto |
| _`/usr/` Verity Signature Partition (x86)_ | `974a71c0-de41-43c3-be5d-5c5ccd1ad2c0` | ditto | ditto |
| _EFI System Partition_ | `c12a7328-f81f-11d2-ba4b-00a0c93ec93b` | VFAT | The ESP used for the current boot is automatically mounted to `/efi/` (or `/boot/` as fallback), unless a different partition is mounted there (possibly via `/etc/fstab`, or because the Extended Boot Loader Partition — see below — exists) or the directory is non-empty on the root disk.  This partition type is defined by the [UEFI Specification](http://www.uefi.org/specifications). |
| _Extended Boot Loader Partition_ | `bc13c2ff-59e6-4262-a352-b275fd6f7172` | Typically VFAT | The Extended Boot Loader Partition (XBOOTLDR) used for the current boot is automatically mounted to <tt>/boot/</tt>, unless a different partition is mounted there (possibly via <tt>/etc/fstab</tt>) or the directory is non-empty on the root disk. This partition type is defined by the [Boot Loader Specification](https://systemd.io/BOOT_LOADER_SPECIFICATION). |
| _Swap_ | `0657fd6d-a4ab-43c4-84e5-0933c84b4f4f` | Swap, optionally in LUKS | All swap partitions on the disk containing the root partition are automatically enabled. If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/swap`. This partition type predates the Discoverable Partitions Specification. |
| _Home Partition_ | `933ac7e1-2eb4-4f13-b844-0e14e2aef915` | Any native, optionally in LUKS | The first partition with this type UUID on the disk containing the root partition is automatically mounted to `/home/`. If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/home`. |
| _Server Data Partition_ | `3b8f8425-20e0-4f3b-907f-1a25a76f98e8` | Any native, optionally in LUKS | The first partition with this type UUID on the disk containing the root partition is automatically mounted to `/srv/`. If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/srv`. |
| _Variable Data Partition_ | `4d21b016-b534-45c2-a9fb-5c16e091fd2d` | Any native, optionally in LUKS | The first partition with this type UUID on the disk containing the root partition is automatically mounted to `/var/` — under the condition that its partition UUID matches the first 128 bits of `HMAC-SHA256(machine-id, 0x4d21b016b53445c2a9fb5c16e091fd2d)` (i.e. the SHA256 HMAC hash of the binary type UUID keyed by the machine ID as read from [`/etc/machine-id`](https://www.freedesktop.org/software/systemd/man/machine-id.html). This special requirement is made because `/var/` (unlike the other partition types listed here) is inherently private to a specific installation and cannot possibly be shared between multiple OS installations on the same disk, and thus should be bound to a specific instance of the OS, identified by its machine ID. If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/var`. |
| _Temporary Data Partition_ | `7ec6f557-3bc5-4aca-b293-16ef5df639d1` | Any native, optionally in LUKS | The first partition with this type UUID on the disk containing the root partition is automatically mounted to `/var/tmp/`. If the partition is encrypted with LUKS, the device mapper file will be named `/dev/mapper/tmp`. Note that the intended mount point is indeed `/var/tmp/`, not `/tmp/`. The latter is typically maintained in memory via <tt>tmpfs</tt> and does not require a partition on disk. In some cases it might be desirable to make `/tmp/` persistent too, in which case it is recommended to make it a symlink or bind mount to `/var/tmp/`, thus not requiring its own partition type UUID. |
| _Generic Linux Data Partition_ | `0fc63daf-8483-4772-8e79-3d69d8477de4` | Any native, optionally in LUKS | No automatic mounting takes place for other Linux data partitions. This partition type should be used for all partitions that carry Linux file systems. The installer needs to mount them explicitly via entries in <tt>/etc/fstab</tt>. Optionally, these partitions may be encrypted with LUKS. This partition type predates the Discoverable Partitions Specification. |

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
