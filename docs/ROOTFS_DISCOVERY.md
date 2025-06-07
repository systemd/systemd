---
title: Boot Components & Root File System Discovery
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Boot Components & Root File System Discovery

The recommended way to boot a [`systemd`](https://systemd.io/) based
[UEFI](https://en.wikipedia.org/wiki/UEFI) system consists primarily of three
components:

1. A boot loader,
   i.e. [`systemd-boot`](https://www.freedesktop.org/software/systemd/man/latest/systemd-boot.html)
   that provides interactive and programmatic control of what precisely to
   boot. It takes care of enumerating all possible boot targets (implementing
   the [Boot Loader
   Specification](https://uapi-group.org/specifications/specs/boot_loader_specification/)),
   potentially presenting it to the user in a menu, but otherwise picking an
   item automatically, implementing boot counting and automatic rollback if
   desired.

2. A [unified kernel image
   ("UKI")](https://uapi-group.org/specifications/specs/unified_kernel_image/),
   i.e. an UEFI PE executable that combines
   [`systemd-stub`](https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html),
   a Linux kernel, and an initial RAM disk ("`initrd`") into one. UKIs are
   self-descriptive: the aforementioned boot loader enumerates these UKIs and
   automatically extracts all information necessary to determine which menu
   entries to generate for them. Within the UKI runtime (very early during
   kernel initialization) the transition from the UEFI firmware code to the
   Linux code takes place, i.e. it executes the fundamental
   `ExitBootServices()` UEFI call that ends PC firmware control,
   and lets the Linux kernel take over.

3. A root file system ("`rootfs`"): this is where the regular OS is
   located. The primary job of the early userspace that is contained in the
   `initrd` that itself is part of the UKI, is to find, set up, and pivot into
   the `rootfs`.

> [!NOTE]
> The above is how `systemd` upstream recommends a system is put together. However,
> distributions differ from this, sometimes massively – in particular when
> their focus is on supporting legacy (i.e. non-UEFI) hardware platforms. We
> believe the above three components are all that's really necessary for a
> robust, simple and comprehensive system, but downstreams might see things
> differently. The above however is supposed to be a guideline for distribution
> developers.

## Execution Environments

Note that these three components are executed within very distinct execution
environments, with very different APIs, drivers and file system access:

| Component | Environment |
|-----------|-------------|
| Boot Loader: `systemd-boot` | UEFI APIs, simple VFAT file system access |
| UKI initially: `systemd-stub` | UEFI APIs, simple VFAT file system access |
| UKI finally: `initrd` | Linux APIs, complex storage and file systems |
| Root File System: `rootfs` | Linux APIs, full OS functionality |

## Structure & Auxiliary Resources

Each of the three components is primarily encapsulated in a single object each:

1. The boot loader is primarily a single PE UEFI binary, called either
   `systemd-boot.efi` or `BOOTX64.EFI` depending on context (the latter name
   contains an architecture identifier, and is different for non-x86-64
   architectures).

2. The UKI is primarily a single PE UEFI binary (i.e. a `.efi` file).

3. The `rootfs` is typically a Linux file system, on a GPT partition table
   disk. Typically, the `rootfs` is placed within some form of container that
   ensures security of the file system, i.e. authenticity, confidentiality
   and integrity via `dm-verity`, `dm-crypt`, `dm-integrity` or a combination
   thereof.

While these three objects are generally enough to boot an OS successfully, in
many cases some parameterization and modularization of the boot is necessary,
hence each of these components is often combined with certain optional,
auxiliary resources:

1. The boot loader can read a configuration file
   [`loader.conf`](https://www.freedesktop.org/software/systemd/man/latest/loader.conf.html),
   find additional drivers, or key material for SecureBoot enrollment in the
   same file system it itself is placed in.

2. `systemd-stub` can find additional parameters (["system
   credentials"](https://systemd.io/CREDENTIALS)), configuration
   (["`confext`"](https://www.freedesktop.org/software/systemd/man/latest/systemd-confext.html)),
   drivers/firmware ("`sysext`") and other resources ("EFI Addons") placed next
   to the location it itself is placed in. We typically call these companion
   resources "sidecars".

4. The `rootfs` often is a combination of one file system for `/usr/`
   ("`usrfs`") and one for the actual root `/`, and possibly further,
   auxiliary file systems, for example `/home/` or `/srv/`.

> [!NOTE]
> Depending on the execution environment the first component (the boot loader)
> might be dispensable. Specifically, on disk images intended solely for use in
> VMs, it might be make sense to tell the firmware to directly boot a UKI,
> letting the VMM's image selection functionality play the role of the boot loader.

> [!NOTE]
> Depending on the execution environment the last component (the `rootfs`)
> might also be dispensable. Specifically, for simpler fixed-purpose, stateless
> applications it might be sufficient to run everything needed directly from
> the `initrd` file system embedded in the UKI, and never transition out of
> this. In this case, conceptually the `initrd` is only an `initrd` from kernel
> PoV, but is already the `rootfs` from a userspace PoV. We usually call these
> types of setups Unified System Image ("USI"), as opposed to UKI.

![Schematic Chart of Root File System Discovery](rootfs-discovery-flow.svg)

## Automatic Discovery on Disks

In the most common case all three components and their sidecars are placed on
the same disk. Specifically:

1. The boot loader is placed in the "EFI System Partition" (ESP), typically at
   the paths `/EFI/BOOT/BOOTX64.EFI` (this is a generic entrypoint binary that
   the firmware executes when you just point it to a disk to boot without any
   further details) and `/EFI/systemd/systemd-bootx64.efi` (this is a more
   specific entrypoint that can be registered persistently in the firmware, to
   give it an explicit starting point). The ESP is a concept defined by the
   UEFI specification and is what the firmware initially looks for and
   mounts. Since VFAT is the only relevant file system type UEFI firmwares have
   to support the ESP is generally a VFAT file system. The aforementioned
   auxiliary, optional resources the boot loader may consume are placed in the
   ESP as well, in particular below the `/loader/` subdirectory.

2. The UKIs may either be placed in the ESP (below the `/EFI/Linux/`
   subdirectory), or in the [Extended Boot Loader
   Partition](https://uapi-group.org/specifications/specs/boot_loader_specification/#the-partitions)
   ("XBOOTLDR"), which can be placed on the same disk as the ESP and is also
   VFAT. XBOOTLDR is an optional concept and it's only *raison d'être* is that
   ESPs sometimes are sized too small by vendors, and do not have enough space
   for multiple UKIs. XBOOTLDR hence serves as a conceptual extension of the
   size-constrained ESP. Sidecars for the UKIs are typically placed in a
   directory next to the UKI they are for, whose name however is suffixed by
   `.d/`, i.e. a UKI `foo.efi` has its sidecars in `foo.efi.d/`.

3. The `rootfs` is placed on the same disk as the ESP/XBOOTLDR, in a partition
   marked with a special GPT partition type. Various other well-known types of
   partitions can be placed next to the `rootfs` and are automatically
   discovered and mounted, see the [Discoverable Partitions
   Specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/)
   for details.

In this common case, discovery of all three components and their sidecars is
fully automatic. Each component derives automatically where to find its
auxiliary resources as well as the next step to transition to, entirely based
on the place itself is running from. There's a full chain of automatic
discovery in place:

1. The firmware picks the disk to boot from (possibly by interactive choice of
   the user), accesses the ESP on it, and invokes the boot loader from it.

2. The boot loader then looks for UKIs, both on the ESP it was invoked from,
   and in the XBOOTLDR partition next to it on the same disk.

3. The UKI's initrd then looks for the `rootfs`, on the same disk the
   UKI was invoked from, i.e. it looks for a partition marked as root next to
   the ESP/XBOOTLDR partition. (This information is passed from UKI to
   userspace via the
   [`LoaderDevicePartUUID`](https://systemd.io/BOOT_LOADER_INTERFACE) EFI
   variable.)

In more complex setups it is possible to specify in more detail where to find
each of these resources:

1. Firmware typically provides a basic boot menu which may be used to choose
   between various relevant boot loaders/entrypoints on multiple disks. This
   is sometimes configurable from the firmware setup tool, as well as from
   userspace via tools such as
   [`bootctl`](https://www.freedesktop.org/software/systemd/man/latest/bootctl.html),
   `efibootmgr` or `kernel-bootcfg`.

2. The `systemd-boot` boot loader may be configured via [`Boot Loader
   Specification Type #1`](https://uapi-group.org/specifications/specs/boot_loader_specification/)
   entries to acquire UKIs or similar from other locations.

3. The `initrd` part of the UKI understands the `root=` (and `mount.usr=`)
   kernel command line switches to look for the `rootfs`/`usrfs` at a
   particular place.

While it is recommended to keep all three components closely together it is
possible via these mechanisms to place all three at completely disparate
locations, too.

## Network Boot

In many cases it is essential to boot an OS from the network instead of a
local disk. This can happen at each of these three components:

1. Many UEFI firmwares support HTTP(S) network boot (usually requires enabling
   in firmware setup). If this is available, it permits downloading a disk image
   from an HTTP server (the URL can either be configured in the firmware setup,
   or be acquired in a DHCP lease). The disk image is then set up as a RAM
   disk, and then processed much like a regular disk: an ESP is searched for
   and the `/EFI/BOOT/BOOTX64.EFI` entrypoint binary is invoked.

2. UKIs can be placed on the same downloaded disk image, within the ESP. If
   multiple different UKIs shall be made accessible from the same boot menu
   this would potentially increase the size of the disk image to prohibitive sizes.
   In order to address this, it is possible to embed Boot
   Loader Specification Type #1 entry files in the ESP instead, which may carry
   references to the UKIs to download and invoke once a choice is made. These
   references can either be full URLs or alternatively simple filenames which
   are then automatically appended to the URL that was used by the firmware
   to acquire the initial boot disk.

3. The `rootfs` can be acquired automatically from a networked source too in a
   flexible fashion. For example, the `initrd` contained in the UKI might
   support NVMe-over-TCP or iSCSI block devices to boot from, supporting the
   whole Linux storage stack. `systemd` also natively [supports downloading the
   `rootfs` from HTTP
   sources](https://www.freedesktop.org/software/systemd/man/latest/systemd-import-generator.html),
   either in a GPT disk image (specifically:
   [DDIs](https://uapi-group.org/specifications/specs/discoverable_disk_image/),
   with `.raw` suffix) or in a `.tar` file, which are placed in system RAM and
   then booted into (these downloads can be downloaded in compressed form and
   are automatically decompressed on-the-fly). This of course requires
   sufficient RAM to be available on the target system, and also means that
   persistency of modifications of the file system is not possible. If this
   mode is used, the URL to acquire the `rootfs` disk image from can be derived
   automatically from the URL that was used to acquire the UKI itself. (This
   information is passed from UKI to userspace via the `LoaderDevicePartURL`
   EFI variable.)

Similarly to the disk-based boot scheme described in the previous section,
discovery of the boot source can be fully automatic, with each
component taking the source of the preceding component into account:
the boot loader can automatically download UKIs from the same source
it itself was downloaded from. Moreover the `initrd` of the UKI can
automatically downloads the `rootfs` from the same source it itself was
downloaded from.

Also, much like in the disk-based boot scheme, it is possible to
specify a different source for a component to replace the automatically-derived URL.
On top of that it is of course possible to mix disk-based and network-based boot:
for example place the boot loader on the local disk,
but use UKIs and `rootfs` from networked sources;
or alternatively place both boot loader and UKIs on the local disk,
and only the `rootfs` on the network.

## Trust & Security

In a modern world of boot integrity, all three of the relevant components as well
as (most of) their sidecars require cryptographic protection. Specifically:

1. The boot loader is typically authenticated by the firmware before invocation
   via UEFI Secure Boot, i.e. checked against a cryptographic certificate list
   persistently stored in the firmware. Note that the various auxiliary
   resources the `systemd-boot` boot loader reads are not individually
   authenticated (i.e. `loader.conf` as well as Type #1 Boot Loader
   Specification entries). Because of this they can typically only be used in a
   very restricted fashion, i.e. configure some UI details as well as menu
   entries. Some options available are ignored if Secure Boot mode is
   enabled. Moreover, even if the text strings shown in the menu entries might
   not be authenticated, the binaries that are invoked once they are selected
   are, as are all their parameters.

2. The UKIs are also authenticated by the firmware via UEFI Secure Boot, and so
   are EFI Addons. `confext` and `sysext` sidecars are protected via
   `dm-verity` and a signature of the root hash is validated against keys in
   the kernel's keyrings. System credentials are authenticated via secrets
   stored in the TPM.

3. Authentication of the `rootfs` and `usrfs` is more variable: depending on
   setup this is either done via `dm-verity` (either pinned by root hash from
   the UKI, or authenticated by signature provided to the kernel, checked
   against the kernel's built-in keyring) or `dm-crypt`+`dm-integrity`
   (protected by TPM or user provided password/FIDO/PKCS#11), or in the network
   case at download time via detached signatures (currently only GPG) or via
   HTTPS certificate validation. Note that by default the automatic discovery
   mechanism of the `rootfs` and its auxiliary file systems does not insist on
   cryptographic protection and authentication before use. However, the
   [`systemd.image_policy=`](https://www.freedesktop.org/software/systemd/man/latest/systemd.image-policy.html)
   kernel command line switch may be used to control precisely what kind of
   protection to require for each such partition.

Note that UEFI Secure Boot is problematic in various ways: it is generally
bound to a certificate list maintained centrally by Microsoft, and thus implies
a complex (and expensive) code signing bureaucracy, that in many cases is
undesirable, particularly in a community Linux world. Moreover, because the
certificate list managed by Microsoft is very large, its security value is
limited: it mostly acts more as denylist of known-bad software rather than as
allowlist of known-good. (If you enroll your own list, things are much better,
but see below.)

### Shim

To make the code signing more palatable to the Linux world the `shim` project
has been developed, which is often used as initial component of the OS boot
(i.e. the firmware would invoke `shim` as component 0, before the components 1,
2, 3 described above). `shim` is primarily relevant for two reasons: it adds
a second set of certificates on top of the UEFI Secure Boot list, maintained by
the OS vendor, and it optionally provides functionality to maintain a local set
of keys ("MOK") in addition to the Microsoft and OS vendor keys.

### Automatic Enrollment of Secure Boot Certificates

The `systemd-boot` boot loader also supports automatic enrollment of
alternative SecureBoot certificates: if the system is booted in the
firmware-provided Secure Boot "Setup Mode", it can automatically enroll
certificates placed inside the ESP into the firmware, replacing any existing
ones if there are any. This mechanism massively enhances the security value of
Secure Boot: you can enroll your own certificates, ensuring that only the
software you want shall be allowed to be run on the system, in a very focused
way. However, do note that this mechanism is only suitable if the hardware
supports it properly, because the Secure Boot certificate
list is also used to authenticate firmware extensions provided by certain
extension boards of PCs (for example graphics cards). Or in other words:
replacing the certificate list with your own might result in unbootable and even
bricked systems. Automatic enrolling of Secure Boot certificates is however a
really good option if the targeted hardware is known to be compatible,
which is in particular the case in VMs.

### Measured Boot and TPMs

Secure Boot is not the only mechanism that can provide boot time integrity
guarantees of the OS. Most modern systems are equipped with a TPM security
chip. It allows components of the boot to issue "measurements" (i.e. submit
a cryptographic hash) of the next step of the boot process as well as of all
inputs they consume to the device, in a fashion that cannot be undone (except
if the system is rebooted). The combination of measurements of all such boot
components can then later be used to protect secrets the TPM can manage: only
if the system is booted in a very specific way such secrets (such as a disk
encryption key) can be revealed to the OS. This hence provides a different form
of protection: instead of making it *a-priori* impossible to boot or consume
untrusted components (as Secure Boot would do it), anything is permitted,
however the TPM would never reveal protected secrets to the OS unless the
components are trusted, in a *a-posteriori* fashion. This generally provides a
more focused security model (as the list of allowed components and the
policies derived thereof are locally maintained instead of world-wide by
Microsoft), however, requires more careful management of OS and firmware
updates. Moreover, it's more compatible with a TOFU security model ("Trust on
first use") rather than a universal trust model.

`systemd-stub` will measure the sidecars it picks up as well as the individual
parts that make up a UKI that are used for boot. `systemd` userspace will also
measure various parts of its resources as does the kernel.

[`systemd-pcrlock`](https://www.freedesktop.org/software/systemd/man/latest/systemd-pcrlock.html),
[`systemd-measure`](https://www.freedesktop.org/software/systemd/man/latest/systemd-measure.html),
[`systemd-cryptenroll`](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html),
[`systemd-cryptsetup`](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptsetup.html)
can be used to manage Measured Boot policies for disk encryption.

Note that Secure Boot and Measured Boot are not exclusive to each other, they
are often used in combination, and can interact (e.g. the Secure Boot
certificate lists are measured as part of the boot process).

### Security of Network Boot

UEFI HTTP boot comes in two flavours: plain HTTP and HTTPS. The latter
typically requires enrolment of TLS server certificates in the system
firmware, but provides transport integrity, authenticity and
confidentiality. Acquiring the various resources via plain HTTP should
generally be sufficient too, as the key resources acquired this way
area generally authenticated before use via other mechanisms, see above.

## Building

The `systemd` project provides various tools to build the various components
necessary to implement the aforementioned boot process:

* The `systemd-boot`, `systemd-stub` components are part of the `systemd`
  source tree.

* The
  [`ukify`](https://www.freedesktop.org/software/systemd/man/latest/ukify.html)
  tool provided by `systemd` can be used to build UKIs, USIs and EFI Addons.

* The `bootctl` tool provided by `systemd` can be used to install the
  `systemd-boot` boot loader to the ESP.

* The
  [`kernel-install`](https://www.freedesktop.org/software/systemd/man/latest/kernel-install.html)
  tool provided by `systemd` can be used to install UKIs to the ESP or
  XBOOTLDR.

* The
  [`systemd-repart`](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html)
  tool can be used to generate `confext` and `sysext` images, as well as
  `rootfs` and `usrfs` images. It can also be used install such images on other
  disks, or to augment minimal disk images on boot with additional partitions,
  or grow them.

* The
  [`systemd-creds`](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html)
  tool can be used to generate system credential files.

* The `systemd-cryptsetup`, `systemd-veritysetup` and `systemd-integritysetup`
  tools can be used to set up cryptographically protected disks at boot.

* [`mkosi`](https://github.com/systemd/mkosi) is a higher level tool that
  combines all of the above to build and sign complete OS images from
  distribution packages, as needed: `initrd` trees, UKIs, USIs,
  `rootfs`/`usrfs`, whole DDIs, `sysext` images, `.tar` files to boot into and
  more.
