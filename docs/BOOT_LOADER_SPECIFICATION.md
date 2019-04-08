---
title: The Boot Loader Specification
---

# The Boot Loader Specification

_TL;DR: Currently there's no common boot scheme across architectures and
platforms for open-source operating systems. There's also little cooperation
between multiple distributions in dual-boot (or triple, … multi-boot)
setups. We'd like to improve this situation by getting everybody to commit to a
single boot configuration format that is based on drop-in files, and thus is
robust, simple, works without rewriting configuration files and is free of
namespace clashes._

The Boot Loader Specification defines a scheme how different operating systems
can cooperatively manage a boot loader configuration directory, that accepts
drop-in files for boot menu items that are defined in a format that is shared
between various boot loader implementations, operating systems, and userspace
programs. The same scheme can be used to prepare OS media for cases where the
firmware includes a boot loader. The target audience for this specification is:

* Boot loader developers, to write a boot loader that directly reads its configuration at runtime from these drop-in snippets
* Firmware developers, to add generic boot loading support directly to the firmware itself
* Distribution and Core OS developers, in order to create these snippets at OS/kernel package installation time
* UI developers, for implementing a user interface that discovers the available boot options
* OS Installer developers, to prepare their installation media and for setting up the initial drop-in directory

## Why is there a need for this specification?

Of course, without this specification things already work mostly fine. But here's why we think this specification is needed:

* To make the boot more robust, as no explicit rewriting of configuration files is required any more
* To allow an out of the box boot experience on any platform without the need of traditional firmware mechanisms (e.g. BIOS calls, UEFI Boot Services)
* To improve dual-boot scenarios. Currently, multiple Linux installations tend to fight over which boot loader becomes the primary one in possession of the MBR, and only that one installation can then update the boot loader configuration of it freely. Other Linux installs have to be manually configured to never touch the MBR and instead install a chain-loaded boot loader in their own partition headers. In this new scheme as all installations share a loader directory no manual configuration has to take place, and all participants implicitly cooperate due to removal of name collisions and can install/remove their own boot menu entries at free will, without interfering with the entries of other installed operating systems.
* Drop-in directories are otherwise now pretty ubiquitous on Linux as an easy way to extend configuration without having to edit, regenerate or manipulate configuration files. For the sake of uniformity, we should do the same for extending the boot menu.
* Userspace code can sanely parse boot loader configuration which is essential with modern BIOSes which do not necessarily initialize USB keyboards anymore during boot, which makes boot menus hard to reach for the user. If userspace code can parse the boot loader configuration, too, this allows for UIs that can select a boot menu item to boot into, before rebooting the machine, thus not requiring interactivity during early boot.
* To unify and thus simplify configuration of the various boot loaders around, which makes configuration of the boot loading process easier for users, administrators and developers alike.
* For boot loaders with configuration _scripts_ such as grub2, adopting this spec allows for mostly static scripts that are generated only once at first installation, but then do not need to be updated anymore as that is done via drop-in files exclusively.

## Why not simply rely on the EFI boot menu logic?

EFI is not ubiquitous, especially not in embedded systems. If you have an EFI
system, it provides a boot options logic that can offer similar
functionality. Here's why we think that it is not enough for our uses:

* The various EFI implementations implement the boot order/boot item logic to different levels. Some firmware implementations do not offer a boot menu at all and instead unconditionally follow the EFI boot order, booting the first item that is working.
* If the firmware setup is used to reset all data usually all EFI boot entries are lost, making the system entirely unbootable, as the firmware setups generally do not offer a UI to define additional boot items. By placing the menu item information on disk, it is always available, regardless if the BIOS setup data is lost.
* Harddisk images should be moveable between machines and be bootable without requiring explicit EFI variables to be set. This also requires that the list of boot options is defined on disk, and not in EFI variables alone.
* EFI is not universal yet (especially on non-x86 platforms), this specification is useful both for EFI and non-EFI boot loaders.
* Many EFI systems disable USB support during early boot to optimize boot times, thus making keyboard input unavailable in the EFI menu. It is thus useful if the OS UI has a standardized way to discover available boot options which can be booted to.

## Technical Details

Everything described below is located on a placeholder file system `$BOOT`. The installer program should pick `$BOOT` according to the following rules:

* On disks with MBR disk labels
  * If the OS is installed on a disk with MBR disk label, and a partition with the MBR type id of 0xEA already exists it should be used as `$BOOT`.
  * Otherwise, if the OS is installed on a disk with MBR disk label, a new partition with MBR type id of 0xEA shall be created, of a suitable size (let's say 500MB), and it should be used as `$BOOT`.
* On disks with GPT disk labels
  * If the OS is installed on a disk with GPT disk label, and a partition with the GPT type GUID of `bc13c2ff-59e6-4262-a352-b275fd6f7172` already exists, it should be used as `$BOOT`.
  * Otherwise, if the OS is installed on a disk with GPT disk label, and an ESP partition (i.e. with the GPT type UID of `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`) already exists and is large enough (let's say 250MB`) and otherwise qualifies, it should be used as `$BOOT`.
  * Otherwise, if the OS is installed on a disk with GPT disk label, and if the ESP partition already exists but is too small, a new suitably sized (let's say 500MB) partition with GPT type GUID of `bc13c2ff-59e6-4262-a352-b275fd6f7172` shall be created and it should be used as `$BOOT`.
  * Otherwise, if the OS is installed on a disk with GPT disk label, and no ESP partition exists yet, a new suitably sized (let's say 500MB) ESP should be created and should be used as `$BOOT`.

This placeholder file system shall be determined during _installation time_, and an fstab entry may be created. It should be mounted to either `/boot/` or `/efi/`. Additional locations like `/boot/efi/`, with `/boot/` being a separate file system, might be supported by implementations. This is not recommended because the mounting of `$BOOT` is then dependent on and requires the mounting of the intermediate file system.

**Note:** _`$BOOT` should be considered **shared** among all OS installations of a system. Instead of maintaining one `$BOOT` per installed OS (as `/boot/` was traditionally handled), all installed OS share the same place to drop in their boot-time configuration._

For systems where the firmware is able to read file systems directly, `$BOOT`
must be a file system readable by the firmware. For other systems and generic
installation and live media, `$BOOT` must be a VFAT (16 or 32) file
system. Applications accessing `$BOOT` should hence not assume that fancier
file system features such as symlinks, hardlinks, access control or case
sensitivity are supported.

This specification defines two types of boot loader entries. The first type is
text based, very simple and suitable for a variety of firmware, architecture
and image types ("Type #1"). The second type is specific to EFI, but allows
single-file images that embed all metadata in the kernel binary itself, which
is useful to cryptographically sign them as one file for the purpose of
SecureBoot ("Type #2").

Not all boot loader entries will apply to all systems. For example, Type #1
entries that use the `efi` key and all Type #2 entries only apply to EFI
systems. Entries using the `architecture` key might specify an architecture that
doesn't match the local one. Boot loaders should ignore all entries that don't
match the local platform and what the boot loader can support, and hide them
from the user. Only entries matching the feature set of boot loader and system
shall be considered and displayed. This allows image builders to put together
images that transparently support multiple different architectures.

### Type #1 Boot Loader Specification Entries

We define two directories below `$BOOT`:

* `$BOOT/loader/` is the directory containing all files needed for Type #1 entries
* `$BOOT/loader/entries/` is the directory containing the drop-in snippets. This directory contains one `.conf` file for each boot menu item.

**Note:** _In all cases the `/loader/` directory should be located directly in the root of the file system. Specifically, if `$BOOT` is the ESP, then `/loader/` directory should be located directly in the root directory of the ESP, and not in the `/EFI/` subdirectory._

Inside the `$BOOT/loader/entries/` directory each OS vendor may drop one or more configuration snippets with the suffix ".conf", one for each boot menu item. The file name of the file is used for identification of the boot item but shall never be presented to the user in the UI. The file name may be chosen freely but should be unique enough to avoid clashes between OS installations. More specifically it is suggested to include the machine ID (`/etc/machine-id` or the D-Bus machine ID for OSes that lack `/etc/machine-id`), the kernel version (as returned by `uname -r`) and an OS identifier (The ID field of `/etc/os-release`). Example: `$BOOT/loader/entries/6a9857a393724b7a981ebb5b8495b9ea-3.8.0-2.fc19.x86_64.conf`.

These configuration snippets shall be Unix-style text files (i.e. line separation with a single newline character), in the UTF-8 encoding. The configuration snippets are loosely inspired on Grub1's configuration syntax. Lines beginning with '#' shall be ignored and used for commenting. The first word of a line is used as key and shall be separated by one or more spaces from its value. The following keys are known:

* `title` shall contain a human readable title string for this menu item. This will be displayed in the boot menu for the item. It is a good idea to initialize this from the `PRETTY_NAME` of `/etc/os-release`. This name should be descriptive and does not have to be unique. If a boot loader discovers two entries with the same title it is a good idea to show more than just the raw title in the UI, for example by appending the `version` field. This field is optional. Example: "Fedora 18 (Spherical Cow)".
* `version` shall contain a human readable version string for this menu item. This is usually the kernel version and is intended for use by OSes to install multiple kernel versions at the same time with the same `title` field. This field shall be in a syntax that is useful for Debian-style version sorts, so that the boot loader UI can determine the newest version easily and show it first or preselect it automatically. This field is optional. Example: `3.7.2-201.fc18.x86_64`.
* `machine-id` shall contain the machine ID of the OS `/etc/machine-id`. This is useful for boot loaders and applications to filter out boot entries, for example to show only a single newest kernel per OS, or to group items by OS, or to maybe filter out the currently booted OS in UIs that want to show only other installed operating systems. This ID shall be formatted as 32 lower case hexadecimal characters (i.e. without any UUID formatting). This key is optional. Example: `4098b3f648d74c13b1f04ccfba7798e8`.
* `linux` refers to the Linux kernel to spawn and shall be a path relative to the `$BOOT` directory. It is recommended that every distribution creates a machine id and version specific subdirectory below `$BOOT` and places its kernels and initial RAM disk images there. Example: `/6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/linux`.
* `initrd` refers to the initrd to use when executing the kernel. This also shall be a path relative to the `$BOOT` directory. This key is optional. This key may appear more than once in which case all specified images are used, in the order they are listed. Example: `6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/initrd`.
* `efi` refers to an arbitrary EFI program. This also takes a path relative to `$BOOT`. If this key is set, and the system is not an EFI system this entry should be hidden.
* `options` shall contain kernel parameters to pass to the Linux kernel to spawn. This key is optional and may appear more than once in which case all specified parameters are used in the order they are listed.
* `devicetree` refers to the binary device tree to use when executing the
kernel. This also shall be a path relative to the `$BOOT` directory. This
key is optional. Example: `6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.armv7hl/tegra20-paz00.dtb`.
* `architecture` refers to the architecture this entry is defined for. The argument should be an architecture identifier, using the architecture vocabulary defined by the EFI specification (i.e. `IA32`, `x64`, `IA64`, `ARM`, `AA64`, …). If specified and this does not match (case insensitively) the local system architecture this entry should be hidden.

Each configuration drop-in snippet must include at least a `linux` or an `efi` key and is otherwise not valid. Here's an example for a complete drop-in file:

    # /boot/loader/entries/6a9857a393724b7a981ebb5b8495b9ea-3.8.0-2.fc19.x86_64.conf
    title        Fedora 19 (Rawhide)
    version      3.8.0-2.fc19.x86_64
    machine-id   6a9857a393724b7a981ebb5b8495b9ea
    options      root=UUID=6d3376e4-fc93-4509-95ec-a21d68011da2
    architecture x64
    linux        /6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/linux
    initrd       /6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/initrd

On EFI systems all Linux kernel images should be EFI images. In order to
increase compatibility with EFI systems it is highly recommended only to
install EFI kernel images, even on non-EFI systems, if that's applicable and
supported on the specific architecture.

Conversely, in order to increase compatibility it is recommended to install
generic kernel images that make few assumptions about the firmware they run on,
i.e. it is a good idea that both images shipped as UEFI PE images and those
which are not don't make unnecessary assumption on the underlying firmware,
i.e. don't hard depend on legacy BIOS calls or UEFI boot services.

Note that these configuration snippets may only reference kernels (and EFI programs) that reside on the same file system as the configuration snippets, i.e. everything referenced must be contained in the same file system. This is by design, as referencing other partitions or devices would require a non-trivial language for denoting device paths. If kernels/initrds are to be read from other partitions/disks the boot loader can do this in its own native configuration, using its own specific device path language, and this is out of focus for this specification. More specifically, on non-EFI systems configuration snippets following this specification cannot be used to spawn other operating systems (such as Windows).

### Type #2 EFI Unified Kernel Images

A unified kernel image is a single EFI PE executable combining an EFI stub
loader, a kernel image, an initramfs image, and the kernel command line. See
the description of the `--uefi` option in
[dracut(8)](http://man7.org/linux/man-pages/man8/dracut.8.html). Such unified
images will be searched for under `$BOOT/EFI/Linux/` and must have the
extension `.efi`. Support for images of this type is of course specific to
systems with EFI firmware. Ignore this section if you work on systems not
supporting EFI.

Images of this type have the advantage that all metadata and payload that makes
up the boot entry is monopolized in a single PE file that can be signed
cryptographically as one for the purpose of EFI SecureBoot.

A valid unified kernel image must contain two PE sections:

* `.cmdline` section with the kernel command line
* `.osrel` section with an embedded copy of the [os-release](https://www.freedesktop.org/software/systemd/man/os-release.html) file describing the image

The `PRETTY_NAME=` and `VERSION_ID=` fields in the embedded os-release file are used the same as `title` and `version` in the "boot loader specification" entries. The `.cmdline` section is used instead of the `options` field. `linux` and `initrd` fields are not necessary, and there is no counterpart for the `machine-id` field.

On EFI, any such images shall be added to the list of valid boot entries.

### Additional notes

Note that these configurations snippets do not need to be the only configuration source for a boot loader. It may extend this list of entries with additional items from other configuration files (for example its own native configuration files) or automatically detected other entries without explicit configuration.

To make this explicitly clear: this specification is designed with "free" operating systems in mind, starting Windows or MacOS is out of focus with these configuration snippets, use boot-loader specific solutions for that. In the text above, if we say "OS" we hence imply "free", i.e. primarily Linux (though this could be easily be extended to the BSDs and whatnot).

Note that all paths used in the configuration snippets use a Unix-style "/" as path separator. This needs to be converted to an EFI-style "\" separator in EFI boot loaders.


## Logic

A _boot loader_ needs a file system driver to discover and read `$BOOT`, then
simply reads all files `$BOOT/loader/entries/*.conf`, and populates its boot
menu with this. On EFI, it then extends this with any unified kernel images
found in `$BOOT/EFI/Linux/*.efi`. It may also add additional entries, for
example a "Reboot into firmware" option. Optionally it may sort the menu based
on the `machine-id` and `version` fields, and possibly others. It uses the file
name to identify specific items, for example in case it supports storing away
default entry information somewhere. A boot loader should generally not modify
these files.

For "Boot Loader Specification Entries" (Type #1), the _kernel package
installer_ installs the kernel and initrd images to `$BOOT` (it is recommended
to place these files in a vendor and OS and installation specific directory)
and then generates a configuration snippet for it, placing this in
`$BOOT/loader/entries/xyz.conf`, with xyz as concatenation of machine id and
version information (see above). The files created by a kernel package are
private property of the kernel package and should be removed along with it.

For "EFI Unified Kernel Images" (Type #2), the vendor or kernel package
installer creates the combined image and drops it into `$BOOT/EFI/Linux/`. This
file is also private property of the kernel package and should be removed along
with it.

A _UI application_ intended to show available boot options shall operate similar to a boot loader, but might apply additional filters, for example by filtering out the booted OS via the machine ID, or by suppressing all but the newest kernel versions.

An _OS installer_ picks the right place for `$BOOT` as defined above (possibly creating a partition and file system for it) and pre-creates the `/loader/entries/` directory in it. It then installs an appropriate boot loader that can read these snippets. Finally, it installs one or more kernel packages.


## Out of Focus

There are a couple of items that are out of focus for this specification:

* If userspace can figure out the available boot options, then this is only useful so much: we'd still need to come up with a way how userspace could communicate to the boot loader the default boot loader entry temporarily or persistently. Defining a common scheme for this is certainly a good idea, but out of focus for this specification.
* This specification is just about "Free" Operating systems. Hooking in other operating systems (like Windows and macOS) into the boot menu is a different story and should probably happen outside of this specification. For example, boot loaders might choose to detect other available OSes dynamically at runtime without explicit configuration (like `systemd-boot` does it), or via native configuration (for example via explicit Grub2 configuration generated once at installation).
* This specification leaves undefined what to do about systems which are upgraded from an OS that does not implement this specification. As the previous boot loader logic was largely handled by in distribution-specific ways we probably should leave the upgrade path (and whether there actually is one) to the distributions. The simplest solution might be to simply continue with the old scheme for old installations and use this new scheme only for new installations.


## Links

[systemd-boot(7)](https://www.freedesktop.org/software/systemd/man/systemd-boot.html)<br>
[bootctl(1)](https://www.freedesktop.org/software/systemd/man/bootctl.html)
