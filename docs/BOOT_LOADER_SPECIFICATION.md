---
title: Boot Loader Specification
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# The Boot Loader Specification

This document defines a set of file formats and naming conventions that allow
the boot loader menu entries to be shared between multiple operating systems
and boot loaders installed on one device.

Operating systems cooperatively manage boot loader menu entry directories that
contain drop-in files, making multi-boot scenarios easy to support. Boot menu
entries are defined via two simple formats that can be understood by different
boot loader implementations, operating systems, and userspace programs. The
same scheme can be used to prepare OS media for cases where the firmware
includes a boot loader.

## Target Audience

The target audience for this specification is:

* Boot loader developers, to write a boot loader that directly reads its
  menu entries from these files
* Firmware developers, to add generic boot loading support directly to the
  firmware itself
* OS installer developers, to create appropriate partitions and set up the
  initial boot loader menu entries
* Distribution developers, to create appropriate menu entry snippets when
  installing or updating kernel packages
* UI developers, to implement user interfaces that list and select among the
  available boot options

## The Partitions

Everything described below is located on one or two partitions. The boot loader
or user-space programs reading the boot loader menu entries should locate them
in the following manner:

* On disks with an MBR partition table:

  * The boot partition — a partition with the type ID of `0xEA` — shall be used
    as the single location for boot loader menu entries.

* On disks with GPT (GUID Partition Table)

  * The EFI System Partition (ESP for short) — a partition with a GPT type GUID
    of `c12a7328-f81f-11d2-ba4b-00a0c93ec93b` — may be used as one of two locations for
    boot loader menu entries.

  * Optionally, an Extended Boot Loader Partition (XBOOTLDR partition for
    short) — a partition with GPT type GUID of
    `bc13c2ff-59e6-4262-a352-b275fd6f7172` — may be used as the second of two
    locations for boot loader menu entries. This partition must be located on
    the same disk as the ESP.

There may be at most one partition of each of the types listed above on the
same disk.

**Note:** _These partitions are **shared** among all OS installations on the
same disk. Instead of maintaining one boot partition per installed OS (as
`/boot/` was traditionally handled), all installed OSes use the same place for
boot loader menu entries._

For systems where the firmware is able to read file systems directly, the ESP
must — and the MBR boot and GPT XBOOTLDR partition should — be a file system
readable by the firmware. For most systems this means VFAT (16 or 32
bit). Applications accessing both partitions should hence not assume that
fancier file system features such as symlinks, hardlinks, access control or
case sensitivity are supported.

### The `$BOOT` Partition Placeholder

In the text below, the placeholder `$BOOT` will be used to refer to the
partition determined as follows:

 1. On disks with an MBR partition table: → the boot partition, as described above

 2. On disks with a GPT partition table: → the XBOOTLDR partition if it exists

 3. Otherwise, on disks with a GPT partition table: → the ESP

`$BOOT` is the *primary* place to put boot menu entry resources into, but
typically not the only one. Most importantly, boot loaders should also pick up
menu entries from the ESP, even if XBOOTLDR exists (for details see below).

### Creating These Partitions

An installer for an operating system should use this logic when selecting or
creating partitions:

  * If a boot partition (in case of MBR) or an XBOOTLDR partition (in case of
    GPT) already exists it should be used as `$BOOT` and used as primary
    location to place boot loader menu resources in.

  * Otherwise, if on GPT and an ESP is found and it is large enough (let's say
    at least 1G) it should be used as `$BOOT` and used as primary location to
    place boot loader menu resources in.

  * Otherwise, if on GPT and neither XBOOTLDR nor ESP exist, an ESP should be
    created of the appropriate size and be used as `$BOOT`, and used as primary
    location to place boot loader menu resources in.

  * Otherwise, a boot partition (in case of MBR) or XBOOTLDR partition (in case
    of GPT) should be created of an appropriate size, and be used as `$BOOT`,
    and used as primary location to place boot loader menu resources in.

These partitions shall be determined during _installation time_, and
`/etc/fstab` entries may be created.

### Mount Points

It is recommended to mount `$BOOT` to `/boot/`, and the ESP to `/efi/`. If
`$BOOT` and the ESP are the same, then either a bind mount or a symlink should
be established making the partition available under both paths.

(Mounting the ESP to `/boot/efi/`, as was traditionally done, is not
recommended. Such a nested setup complicates an implementation via direct
`autofs` mounts — as implemented by `systemd` for example —, as establishing
the inner `autofs` will trigger the outer one. Mounting the two partitions via
`autofs` is recommended because the simple VFAT file system has weak data
integrity properties and should remain unmounted whenever possible.)

## Boot Loader Entries

This specification defines two types of boot loader entries. The first type is
text based, very simple, and suitable for a variety of firmware, architecture
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

Note that the three partitions described above are not supposed to be the
exclusive territory of this specification. This specification only defines
semantics of the `/loader/entries/` directory (along with the companion file
`/loader/entries.srel`) and the `/EFI/Linux/` directory inside the file system,
but it doesn't intend to define contents of the rest of the file system. Boot
loaders, firmware, and other software implementing this specification may
choose to place other files and directories in the same file system. For
example, boot loaders that implement this specification might install their own
boot code on the same partition; this is particularly common in the case of the
ESP. Implementations of this specification must be able to operate correctly if
files or directories other than `/loader/entries/` and `/EFI/Linux/` are found
in the top level directory. Implementations that add their own files or
directories to the file systems should use well-named directories, to make name
collisions between multiple users of the file system unlikely.

### Type #1 Boot Loader Specification Entries

`/loader/entries/` in `$BOOT` is the primary directory containing Type #1
drop-in snippets defining boot entries, one `.conf` file for each boot menu
item. Each OS may provide one or more such entries.

If the ESP is separate from `$BOOT` it may also contain a `/loader/entries/`
directory, where the boot loader should look for boot entry snippets, as an
additional source. The boot loader should enumerate both directories and
present a merged list to the user. Note that this is done for compatibility
only: while boot loaders should look in both places, OSes should only add their
files to `$BOOT`.

**Note:** _In all cases the `/loader/entries/` directory should be located
directly in the root of the file system. Specifically, the `/loader/entries/`
directory should **not** be located under the `/EFI/` subdirectory on the ESP._

The file name of the boot entry snippets is used for identification of the boot
item but shall never be presented to the user in the UI. The file name may be
chosen freely but should be unique enough to avoid clashes between OS
installations. More specifically, it is suggested to include the `entry-token`
(see
[kernel-install](https://www.freedesktop.org/software/systemd/man/kernel-install.html))
or machine ID (see
[/etc/machine-id](https://www.freedesktop.org/software/systemd/man/machine-id.html)),
and the kernel version (as returned by `uname -r`, including the OS
identifier), so that the whole filename is
`$BOOT/loader/entries/<entry-token-or-machine-id>-<version>.conf`.

Example: `$BOOT/loader/entries/6a9857a393724b7a981ebb5b8495b9ea-3.8.0-2.fc19.x86_64.conf`.

In order to maximize compatibility with file system implementations and
restricted boot loader environments, and to minimize conflicting character use
with other programs, file names shall be chosen from a restricted character
set: ASCII upper and lower case characters, digits, "+", "-", "_" and ".".
Also, the file names should have a length of at least one and at most 255
characters (including the file name suffix).

These boot loader menu snippets shall be UNIX-style text files (i.e. lines
separated by a single newline character), in the UTF-8 encoding. The
boot loader menu snippets are loosely inspired by Grub1's configuration syntax.
Lines beginning with "#" are used for comments and shall be ignored. The first
word of a line is used as key and is separated by one or more spaces from the
value.

#### Type #1 Boot Loader Entry Keys

The following keys are recognized:

* `title` is a human-readable title for this menu item to be displayed in the
  boot menu. It is a good idea to initialize this from the `PRETTY_NAME=` of
  [os-release](https://www.freedesktop.org/software/systemd/man/os-release.html).
  This name should be descriptive and does not have to be unique. If a boot
  loader discovers two entries with the same title it should show more than
  just the raw title in the UI, for example by appending the `version`
  field. This field is optional.

  Example: `title Fedora 18 (Spherical Cow)`

* `version` is a human-readable version for this menu item. This is usually the
  kernel version and is intended for use by OSes to install multiple kernel
  versions with the same `title` field. This field is used for sorting entries,
  so that the boot loader can order entries by age or select the newest one
  automatically. This field is optional.

  See [Sorting](#sorting) below.

  Example: `version 3.7.2-201.fc18.x86_64`

* `machine-id` is the machine ID of the OS. This can be used by boot loaders
  and applications to filter out boot entries, for example to show only a
  single newest kernel per OS, to group items by OS, or to filter out the
  currently booted OS when showing only other installed operating systems.
  This ID shall be formatted as 32 lower case hexadecimal characters
  (i.e. without any UUID formatting). This key is optional.

  Example: `machine-id 4098b3f648d74c13b1f04ccfba7798e8`

* `sort-key` is a short string used for sorting entries on display. This should
  typically be initialized from the `IMAGE_ID=` or `ID=` fields of
  [os-release](https://www.freedesktop.org/software/systemd/man/os-release.html),
  possibly with an additional suffix. This field is optional.

  Example: `sort-key fedora`

* `linux` is the Linux kernel image to execute and takes a path relative to the
  root of the file system containing the boot entry snippet itself. It is
  recommended that every distribution creates an entry-token/machine-id and
  version specific subdirectory and places its kernels and initrd images there
  (see below).

  Example: `linux /6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/linux`

* `initrd` is the initrd `cpio` image to use when executing the kernel. This key
  may appear more than once in which case all specified images are used, in the
  order they are listed.

  Example: `initrd 6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/initrd`

* `efi` refers to an arbitrary EFI program. If this key is set, and the system
  is not an EFI system, this entry should be hidden.

* `options` shall contain kernel parameters to pass to the Linux kernel to
  spawn. This key is optional and may appear more than once in which case all
  specified parameters are combined in the order they are listed.

  Example: `options root=UUID=6d3376e4-fc93-4509-95ec-a21d68011da2 quiet`

* `devicetree` refers to the binary device tree to use when executing the
  kernel. This key is optional.

  Example: `devicetree 6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.armv7hl/tegra20-paz00.dtb`

* `devicetree-overlay` refers to a list of device tree overlays that should be
  applied by the boot loader. Multiple overlays are separated by spaces and
  applied in the same order as they are listed. This key is optional but
  depends on the `devicetree` key.

  Example: `devicetree-overlay /6a9857a393724b7a981ebb5b8495b9ea/overlays/overlay_A.dtbo /6a9857a393724b7a981ebb5b8495b9ea/overlays/overlay_B.dtbo`

* `architecture` refers to the architecture this entry is for. The argument
  should be an architecture identifier, using the architecture vocabulary
  defined by the EFI specification (i.e. `IA32`, `x64`, `IA64`, `ARM`, `AA64`,
  …). If specified and it does not match the local system architecture this
  entry should be hidden. The comparison should be done case-insensitively.

  Example: `architecture aa64`

Each boot loader menu entry drop-in snippet must include at least a `linux` or an `efi`
key. Here is an example for a complete drop-in file:

    # /boot/loader/entries/6a9857a393724b7a981ebb5b8495b9ea-3.8.0-2.fc19.x86_64.conf
    title        Fedora 19 (Rawhide)
    sort-key     fedora
    machine-id   6a9857a393724b7a981ebb5b8495b9ea
    version      3.8.0-2.fc19.x86_64
    options      root=UUID=6d3376e4-fc93-4509-95ec-a21d68011da2 quiet
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

When Type #1 boot loader menu entry snippets refer to other files (for `linux`,
`initrd`, `efi`, `devicetree`, and `devicetree-overlay`), those files must be
located on the same partition, and the paths must be absolute paths relative to
the root of that file system. The naming of those files can be chosen by the
installer. A recommended scheme is described in the next section. Paths should
be normalized, i.e. not include `..`, `.` or a sequence of more than one
`/`. Paths may be prefixed with a `/`, but this is optional and has the same
effect as paths without it: all paths are always relative to the root directory
of the partition they are referenced from.

Even though the backing file system is typically case-insensitive (i.e. VFAT)
it is strongly recommended to reference files in the casing actually used for
the directories/files, so that placing these files on other file systems is
still safe and robust.

### Recommended Directory Layout for Additional Files

It is recommended to place the kernel and other other files comprising a single
boot loader entry in a separate directory:
`/<entry-token-or-machine-id>/<version>/`. This naming scheme uses the same
elements as the boot loader menu entry snippet, providing the same level of
uniqueness.

Example: `$BOOT/6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/linux`
         `$BOOT/6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/initrd`

Other naming schemes are possible. In particular, traditionally a flat naming
scheme with files in the root directory was used. This is not recommended
because it is hard to avoid conflicts in a multi-boot installation.

### Standard-conformance Marker File

Unfortunately, there are implementations of boot loading infrastructure that
are also using the `/loader/entries/` directory, but install files that do not
follow this specification. In order to minimize confusion, a boot loader
implementation may place the file `/loader/entries.srel` next to the
`/loader/entries/` directory containing the ASCII string `type1` (followed by a
UNIX newline). Tools that need to determine whether an existing directory
implements the semantics described here may check for this file and contents:
if it exists and contains the mentioned string, it shall assume a
standards-compliant implementation is in place. If it exists but contains a
different string it shall assume other semantics are implemented. If the file
does not exist, no assumptions should be made.

### Type #2 EFI Unified Kernel Images

A unified kernel image is a single EFI PE executable combining an EFI stub
loader, a kernel image, an initrd image, and the kernel command line. See
[systemd-stub(7)](https://www.freedesktop.org/software/systemd/man/systemd-stub.html)
for details. The primary place for such unified images is the `/EFI/Linux/`
directory in `$BOOT`. Operating systems should place unified EFI kernels only
in the `$BOOT` partition. Boot loaders should also look in the `/EFI/Linux/` of
the ESP — if it is different from `$BOOT` — and present a merged list of menu
entries from both partitions. Regardless if placed in the primary or secondary
location: the files must have the extension `.efi`.  Support for images of this
type is of course specific to systems with EFI firmware. Ignore this section if
you work on systems not supporting EFI.

Type #2 file names should be chosen from the same restricted character set as
Type #1 described above (but with the file name suffix of `.efi` instead of
`.conf`).

Images of this type have the advantage that all metadata and payload that makes
up the boot entry is contained in a single PE file that can be signed
cryptographically as one for the purpose of EFI SecureBoot.

A valid unified kernel image in the `/EFI/Linux/` directory must contain two PE sections:

* `.cmdline` section with the kernel command line,
* `.osrel` section with an embedded copy of the
  [os-release](https://www.freedesktop.org/software/systemd/man/os-release.html)
  file describing the image.

The `PRETTY_NAME=` and `VERSION_ID=` fields in the embedded `os-release` file
are used the same as `title` and `version` in the Type #1 entries. The
`.cmdline` section is used instead of the `options` field. `linux` and `initrd`
fields are not necessary, and there is no counterpart for the `machine-id`
field.

On EFI, any such images shall be added to the list of valid boot entries.

### Additional Notes

Note that these boot entry snippets and unified kernels do not need to be the
only menu entry sources for a boot loader. It may extend this list of
entries with additional items from other configuration files (for example its
own native configuration files) or automatically detected other entries without
explicit configuration.

To make this explicitly clear: this specification is designed with "free"
operating systems in mind, starting Windows or MacOS is out of focus with these
boot loader menu entry snippets, use boot-loader specific solutions for
that. In the text above, if we say "OS" we hence imply "free", i.e. primarily
Linux (though this could be easily be extended to the BSDs and whatnot).

Note that all paths used in the boot loader menu entry snippets use a
Unix-style "/" as path separator. This needs to be converted to an EFI-style
"\\" separator in EFI boot loaders.


## Locating Boot Entries

A _boot loader_ locates the XBOOTLDR partition and the ESP, then simply reads
all the files `/loader/entries/*.conf` in them, and populates its boot menu
(and handle gracefully if one of the two partitions is missing). On EFI, it
then extends this with any unified kernel images found in `/EFI/Linux/*.efi` in
the two partitions. It may also add additional entries, for example a "Reboot
into firmware" option.  Optionally it may sort the menu based on the
`sort-key`, `machine-id` and `version` fields, and possibly others. It uses the
file name to identify specific items, for example in case it supports storing
away default entry information somewhere. A boot loader should generally not
modify these files.

For "Boot Loader Specification Entries" (Type #1), the _kernel package
installer_ installs the kernel and initrd images to `$BOOT`. It is recommended
to place these files in a vendor and OS and installation specific directory. It
then generates a boot loader menu entry snippet, placing it in
`$BOOT/loader/entries/xyz.conf`, with "xyz" as concatenation of
entry-token/machine-id and version information (see above). The files created
by a kernel package are tied to the kernel package and should be removed along
with it.

For "EFI Unified Kernel Images" (Type #2), the vendor or kernel package
installer should create the combined image and drop it into
`$BOOT/EFI/Linux/`. This file is also tied to the kernel package and should be
removed along with it.

A _UI application_ intended to show available boot options shall operate
similarly to a boot loader (and thus search both `$BOOT` and the ESP if
distinct), but might apply additional filters, for example by filtering the
booted OS via the machine ID, or by suppressing all but the newest kernel
versions.

An _OS installer_ picks the right place for `$BOOT` as defined above (possibly
creating a partition and file system for it) and creates the `/loader/entries/`
directory and the `/loader/entries.srel` file in it (the latter only if the
directory didn't exist yet). It then installs an appropriate boot loader that
can read these snippets. Finally, it installs one or more kernel packages.

## Boot counting

The main idea is that when boot entries are initially installed, they are
marked as "indeterminate" and assigned a number of boot attempts. Each time the
boot loader tries to boot an entry, it decreases this count by one. If the
operating system considers the boot as successful, it removes the counter
altogether and the entry becomes "good". Otherwise, once the assigned number of
boots is exhausted, the entry is marked as "bad".

Which boots are "successful" is determined by the operating system. systemd
provides a generic mechanism that can be extended with arbitrary checks and
actions, see [Automatic Boot Assessment](AUTOMATIC_BOOT_ASSESSMENT.md), but the
boot counting mechanism described in this specification can also be used with
other implementations.

The boot counting data is stored in the name of the boot loader entry. A boot
loader entry file name may contain a plus (`+`) followed by a number. This may
optionally be followed by a minus (`-`) followed by a second number. The dot
(`.`) and file name suffix (`conf` of `efi`) must immediately follow. Boot
counting is enabled for entries which match this pattern.

The first number is the "tries left" counter signifying how many attempts to boot
this entry shall still be made. The second number is the "tries done" counter,
showing how many failed attempts to boot it have already been made. Each time
a boot loader entry marked this way is booted, the first counter is decremented,
and the second one incremented. (If the second counter is missing,
then it is assumed to be equivalent to zero.) If the "tries left" counter is
above zero the entry is still considered "indeterminate". A boot entry with the
"tries left" counter at zero is considered "bad".

If the boot attempt completed successfully the entry's counters are removed
from the name (entry state becomes "good"), thus turning off boot counting for
this entry.

## Sorting

The boot loader menu should generally show entries in some order meaningful to
the user. The `title` key is free-form and not suitable to be used as the
primary sorting key. Instead, the boot loader should use the following rules:

1. Entries which are subject to boot counting and are marked as "bad", should
   be sorted later than all other entries. Entries which are marked as
   "indeterminate" or "good" (or were not subject to boot counting at all),
   are thus sorted earlier.

2. If `sort-key` is set on both entries, use in order of priority,
   the `sort-key` (A-Z, increasing [alphanumerical order](#alphanumerical-order)),
   `machine-id` (A-Z, increasing alphanumerical order),
   and `version` keys (decreasing [version order](#version-order)).

3. If `sort-key` is set on one entry, it sorts earlier.

4. At the end, if necessary, when `sort-key` is not set or those fields are not
   set or are all equal, the boot loader should sort using the file name of the
   entry (decreasing version sort), with the suffix removed.

**Note:** _This description assumes that the boot loader shows entries in a
traditional menu, with newest and "best" entries at the top, thus entries with
a higher version number are sorter *earlier*. The boot loader is free to
use a different direction (or none at all) during display._

**Note:** _The boot loader should allow booting "bad" entries, e.g. in case no
other entries are left or they are unusable for other reasons. It may
deemphasize or hide such entries by default._

**Note:** _"Bad" boot entries have a suffix of "+0-`n`", where `n` is the
number of failed boot attempts. Removal of the suffix is not necessary for
comparisons described by the last point above. In the unlikely scenario that we
have multiple such boot entries that differ only by the boot counting data, we
would sort them by `n`._

### Alphanumerical Order

Free-form strings and machine IDs should be compared using a method equivalent
to [strcmp(3)](https://man7.org/linux/man-pages/man3/strcmp.3.html) on their
UTF-8 representations. If just one of the strings is unspecified or empty, it
compares lower. If both strings are unspecified or empty, they compare equal.

### Version Order

The following method should be used to compare version strings. The algorithm
is based on rpm's `rpmvercmp()`, but not identical.

ASCII letters (`a-z`, `A-Z`) and digits (`0-9`) form alphanumerical components of the version.
Minus (`-`) separates the version and release parts.
Dot (`.`) separates parts of version or release.
Tilde (`~`) is a prefix that always compares lower.
Caret (`^`) is a prefix that always compares higher.

Both strings are compared from the beginning until the end, or until the
strings are found to compare as different. In a loop:
1. Any characters which are outside of the set of listed above (`a-z`, `A-Z`, `0-9`, `-`, `.`, `~`, `^`)
   are skipped in both strings. In particular, this means that non-ASCII characters
   that are Unicode digits or letters are skipped too.
2. If one of the strings has ended: if the other string hasn't, the string that
   has remaining characters compares higher. Otherwise, the strings compare
   equal.
3. If the remaining part of one of strings starts with `~`:
   if other remaining part does not start with `~`,
   the string with `~` compares lower. Otherwise, both tilde characters are skipped.
4. The check from point 2. is repeated here.
5. If the remaining part of one of strings starts with `-`:
   if the other remaining part does not start with `-`,
   the string with `-` compares lower. Otherwise, both minus characters are skipped.
6. If the remaining part of one of strings starts with `^`:
   if the other remaining part does not start with `^`,
   the string with `^` compares higher. Otherwise, both caret characters are skipped.
6. If the remaining part of one of strings starts with `.`:
   if the other remaining part does not start with `.`,
   the string with `.` compares lower. Otherwise, both dot characters are skipped.
7. If either of the remaining parts starts with a digit, numerical prefixes are
   compared numerically. Any leading zeroes are skipped.
   The numerical prefixes (until the first non-digit character) are evaluated as numbers.
   If one of the prefixes is empty, it evaluates as 0.
   If the numbers are different, the string with the bigger number compares higher.
   Otherwise, the comparison continues at the following characters at point 1.
8. Leading alphabetical prefixes are compared alphabetically.
   The substrings are compared letter-by-letter.
   If both letters are the same, the comparison continues with the next letter.
   Capital letters compare lower than lower-case letters (`A < a`).
   When the end of one substring has been reached (a non-letter character or the end
   of the whole string), if the other substring has remaining letters, it compares higher.
   Otherwise, the comparison continues at the following characters at point 1.

Examples (with '' meaning the empty string):

* `11 == 11`
* `systemd-123 == systemd-123`
* `bar-123 < foo-123`
* `123a > 123`
* `123.a > 123`
* `123.a < 123.b`
* `123a > 123.a`
* `11α == 11β`
* `A < a`
* '' < `0`
* `0.` > `0`
* `0.0` > `0`
* `0` < `~`
* '' < `~`

Note: [systemd-analyze](https://www.freedesktop.org/software/systemd/man/systemd-analyze.html)
implements this version comparison algorithm as
```
systemd-analyze compare-versions <version-a> <version-b>
```

## Additional discussion

### Why is there a need for this specification?

This specification brings the following advantages:

* Installation of new boot entries is more robust, as no explicit rewriting of
  configuration files is required.

* It allows an out-of-the-box boot experience on any platform without the need
  of traditional firmware mechanisms (e.g. BIOS calls, UEFI Boot Services).

* It improves dual-boot scenarios. Without cooperation, multiple Linux
  installations tend to fight over which boot loader becomes the primary one in
  possession of the MBR or the boot partition, and only that one installation
  can then update the boot loader configuration. Other Linux installs have to
  be manually configured to never touch the MBR and instead install a
  chain-loaded boot loader in their own partition headers. In this new scheme
  all installations share a loader directory and no manual configuration has to
  take place. All participants implicitly cooperate due to removal of name
  collisions and can install/remove their own boot menu entries without
  interfering with the entries of other installed operating systems.

* Drop-in directories are now pretty ubiquitous on Linux as an easy way to
  extend boot loader menus without having to edit, regenerate or manipulate
  configuration files. For the sake of uniformity, we should do the same for
  the boot menu.

* Userspace code can sanely parse boot loader menu entries which is essential
  with modern firmware which does not necessarily initialize USB keyboards
  during boot, which makes boot menus hard to reach for the user. If userspace
  code can parse the boot loader menu entries too, UI can be written that
  select a boot menu item to boot into before rebooting the machine, thus not
  requiring interactivity during early boot.

* To unify and thus simplify menu entries of the various boot loaders, which
  makes configuration of the boot loading process easier for users,
  administrators, and developers alike.

* For boot loaders with configuration _scripts_ such as grub2, adopting this
  spec allows for mostly static scripts that are generated only once at first
  installation, but then do not need to be updated anymore as that is done via
  drop-in files exclusively.

### Why not simply rely on the EFI boot menu logic?

EFI is not ubiquitous, especially not in embedded systems. But even on systems
with EFI, which provides a boot options logic that can offer similar
functionality, this specification is still needed for the following reasons:

* The various EFI implementations implement the boot order/boot item logic to
  different levels. Some firmware implementations do not offer a boot menu at
  all and instead unconditionally follow the EFI boot order, booting the first
  item that is working.

* If the firmware setup is used to reset data, usually all EFI boot entries
  are lost, making the system entirely unbootable, as the firmware setups
  generally do not offer a UI to define additional boot items. By placing the
  menu item information on disk, it is always available, even if the firmware
  configuration is lost.

* Harddisk images should be movable between machines and be bootable without
  requiring firmware configuration. This also requires that the list
  of boot options is defined on disk, and not in EFI variables alone.

* EFI is not universal yet (especially on non-x86 platforms), this
  specification is useful both for EFI and non-EFI boot loaders.

* Many EFI systems disable USB support during early boot to optimize boot
  times, thus making keyboard input unavailable in the EFI menu. It is thus
  useful if the OS UI has a standardized way to discover available boot options
  which can be booted to.

### Why is the version comparison logic so complicated?

The `sort-key` allows us to group entries by "operating system", e.g. all
versions of Fedora together, no matter if they identify themselves as "Fedora
Workstation" or "Fedora Rawhide (prerelease)". The `sort-key` was introduced
only recently, so we need to provide a meaningful order for entries both with
and without it. Since it is a new concept, it is assumed that entries with
`sort-key` are newer.

In a traditional menu with entries displayed vertically, we want names to be
sorter alpabetically (CentOS, Debian, Fedora, OpenSUSE, …), it would be strange
to have them in reverse order. But when multiple kernels are available for the
same installation, we want to display the latest kernel with highest priority,
i.e. earlier in the list.

### Why do you use file renames to store the counter? Why not a regular file?

Mainly two reasons: it's relatively likely that renames can be implemented
atomically even in simpler file systems, as renaming generally avoids
allocating or releasing data blocks. Writing to file contents has a much bigger
chance to be result in incomplete or corrupt data. Moreover renaming has the
benefit that the boot count metadata is directly attached to the boot loader
entry file, and thus the lifecycle of the metadata and the entry itself are
bound together. This means no additional clean-up needs to take place to drop
the boot loader counting information for an entry when it is removed.

### Why not use EFI variables for storing the boot counter?

The memory chips used to back the persistent EFI variables are generally not of
the highest quality, hence shouldn't be written to more than necessary. This
means we can't really use it for changes made regularly during boot, but should
use it only for seldom-made configuration changes.

### Out of Focus

There are a couple of items that are out of focus for this specification:

* If userspace can figure out the available boot options, then this is only
  useful so much: we'd still need to come up with a way how userspace could
  communicate to the boot loader the default boot loader entry temporarily or
  persistently. Defining a common scheme for this is certainly a good idea, but
  out of focus for this specification.

* This specification is just about "Free" Operating systems. Hooking in other
  operating systems (like Windows and macOS) into the boot menu is a different
  story and should probably happen outside of this specification. For example,
  boot loaders might choose to detect other available OSes dynamically at
  runtime without explicit configuration (like `systemd-boot` does it), or via
  native configuration (for example via explicit Grub2 configuration generated
  once at installation).

* This specification leaves undefined what to do about systems which are
  upgraded from an OS that does not implement this specification. As the
  previous boot loader logic was largely handled by in distribution-specific
  ways we probably should leave the upgrade path (and whether there actually is
  one) to the distributions. The simplest solution might be to simply continue
  with the old scheme for old installations and use this new scheme only for
  new installations.

* Referencing kernels or initrds on other partitions other than the partition
  containing the Type #1 boot loader entry. This is by design, as specifying
  other partitions or devices would require a non-trivial language for denoting
  device paths. In particular this means that on non-EFI systems boot loader
  menu entry snippets following this specification cannot be used to spawn
  other operating systems (such as Windows).


## Links

[GUID Partition Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)<br>
[Boot Loader Interface](BOOT_LOADER_INTERFACE.md)<br>
[Discoverable Partitions Specification](DISCOVERABLE_PARTITIONS.md)<br>
[`systemd-boot(7)`](https://www.freedesktop.org/software/systemd/man/systemd-boot.html)<br>
[`bootctl(1)`](https://www.freedesktop.org/software/systemd/man/bootctl.html)<br>
[`systemd-gpt-auto-generator(8)`](https://www.freedesktop.org/software/systemd/man/systemd-gpt-auto-generator.html)
