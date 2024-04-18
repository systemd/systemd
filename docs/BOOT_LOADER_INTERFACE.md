---
title: Boot Loader Interface
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# The Boot Loader Interface

systemd can interface with the boot loader to receive performance data and
other information, and pass control information. This is only supported on EFI
systems. Data is transferred between the boot loader and systemd in EFI
variables. All EFI variables use the vendor UUID
`4a67b082-0a4c-41cf-b6c7-440b29bb8c4f`.

* The EFI Variable `LoaderTimeInitUSec` contains the timestamp in microseconds
  when the loader was initialized. This value is the time spent in the firmware
  for initialization, it is formatted as numeric, NUL-terminated, decimal
  string, in UTF-16.

* The EFI Variable `LoaderTimeExecUSec` contains the timestamp in microseconds
  when the loader finished its work and is about to execute the kernel. The
  time spent in the loader is the difference between `LoaderTimeExecUSec` and
  `LoaderTimeInitUSec`. This value is formatted the same way as
  `LoaderTimeInitUSec`.

* The EFI variable `LoaderDevicePartUUID` contains the partition GUID of the
  ESP the boot loader was run from formatted as NUL-terminated UTF16 string, in
  normal GUID syntax.

* The EFI variable `LoaderConfigTimeout` contains the boot menu timeout
  currently in use. It may be modified both by the boot loader and by the
  host. The value should be formatted as numeric, NUL-terminated, decimal
  string, in UTF-16. The time is specified in seconds. In addition some
  non-numeric string values are also accepted. A value of `menu-force`
  will disable the timeout and show the menu indefinitely. If set to `0` or
  `menu-hidden` the default entry is booted immediately without showing a menu.
  Unless a value of `menu-disabled` is set, the boot loader should provide a
  way to interrupt this by for example listening for key presses for a brief
  moment before booting.

* Similarly, the EFI variable `LoaderConfigTimeoutOneShot` contains a boot menu
  timeout for a single following boot. It is set by the OS in order to request
  display of the boot menu on the following boot. When set overrides
  `LoaderConfigTimeout`. It is removed automatically after being read by the
  boot loader, to ensure it only takes effect a single time. This value is
  formatted the same way as `LoaderConfigTimeout`. If set to `0` the boot menu
  timeout is turned off, and the menu is shown indefinitely.

* The EFI variable `LoaderEntries` may contain a series of boot loader entry
  identifiers, one after the other, each individually NUL terminated. This may
  be used to let the OS know which boot menu entries were discovered by the
  boot loader. A boot loader entry identifier should be a short, non-empty
  alphanumeric string (possibly containing `-`, too). The list should be in the
  order the entries are shown on screen during boot. See below regarding a
  recommended vocabulary for boot loader entry identifiers.

* The EFI variable `LoaderEntryDefault` contains the default boot loader entry
  to use. It contains a NUL-terminated boot loader entry identifier.

* Similarly, the EFI variable `LoaderEntryOneShot` contains the default boot
  loader entry to use for a single following boot. It is set by the OS in order
  to request booting into a specific menu entry on the following boot. When set
  overrides `LoaderEntryDefault`. It is removed automatically after being read
  by the boot loader, to ensure it only takes effect a single time. This value
  is formatted the same way as `LoaderEntryDefault`.

* The EFI variable `LoaderEntrySelected` contains the boot loader entry
  identifier that was booted. It is set by the boot loader and read by
  the OS in order to identify which entry has been used for the current boot.

* The EFI variable `LoaderFeatures` contains a 64-bit unsigned integer with a
  number of flags bits that are set by the boot loader and passed to the OS and
  indicate the features the boot loader supports. Specifically, the following
  bits are defined:

  * `1 << 0` → The boot loader honours `LoaderConfigTimeout` when set.
  * `1 << 1` → The boot loader honours `LoaderConfigTimeoutOneShot` when set.
  * `1 << 2` → The boot loader honours `LoaderEntryDefault` when set.
  * `1 << 3` → The boot loader honours `LoaderEntryOneShot` when set.
  * `1 << 4` → The boot loader supports boot counting as described in [Automatic Boot Assessment](/AUTOMATIC_BOOT_ASSESSMENT).
  * `1 << 5` → The boot loader supports looking for boot menu entries in the Extended Boot Loader Partition.
  * `1 << 6` → The boot loader supports passing a random seed to the OS.
  * `1 << 13` → The boot loader honours `menu-disabled` option when set.

* The EFI variable `LoaderSystemToken` contains binary random data,
  persistently set by the OS installer. Boot loaders that support passing
  random seeds to the OS should use this data and combine it with the random
  seed file read from the ESP. By combining this random data with the random
  seed read off the disk before generating a seed to pass to the OS and a new
  seed to store in the ESP the boot loader can protect itself from situations
  where "golden" OS images that include a random seed are replicated and used
  on multiple systems. Since the EFI variable storage is usually independent
  (i.e. in physical NVRAM) of the ESP file system storage, and only the latter
  is part of "golden" OS images, this ensures that different systems still come
  up with different random seeds. Note that the `LoaderSystemToken` is
  generally only written once, by the OS installer, and is usually not touched
  after that.

If `LoaderTimeInitUSec` and `LoaderTimeExecUSec` are set, `systemd-analyze`
will include them in its boot-time analysis.  If `LoaderDevicePartUUID` is set,
systemd will mount the ESP that was used for the boot to `/boot`, but only if
that directory is empty, and only if no other file systems are mounted
there. The `systemctl reboot --boot-loader-entry=…` and `systemctl reboot
--boot-loader-menu=…` commands rely on the `LoaderFeatures` ,
`LoaderConfigTimeoutOneShot`, `LoaderEntries`, `LoaderEntryOneShot`
variables.

## Boot Loader Entry Identifiers

While boot loader entries may be named relatively freely, it's highly
recommended to follow the following rules when picking identifiers for the
entries, so that programs (and users) can derive basic context and meaning from
the identifiers as passed in `LoaderEntries`, `LoaderEntryDefault`,
`LoaderEntryOneShot`, `LoaderEntrySelected`, and possibly show nicely localized
names for them in UIs.

1. When boot loader entries are defined through the
   [Boot Loader Specification](https://uapi-group.org/specifications/specs/boot_loader_specification/)
   files, the identifier should be derived directly from the file name,
   but with the `.conf` (Type #1 snippets) or `.efi` (Type #2 images)
   suffix removed.

2. Entries automatically discovered by the boot loader (as opposed to being
   configured in configuration files) should generally have an identifier
   prefixed with `auto-`.

3. Boot menu entries referring to Microsoft Windows installations should either
   use the identifier `windows` or use the `windows-` prefix for the
   identifier. If a menu entry is automatically discovered, it should be
   prefixed with `auto-`, see above (Example: this means an automatically
   discovered Windows installation might have the identifier `auto-windows` or
   `auto-windows-10` or so.).

4. Similarly, boot menu entries referring to Apple macOS installations should
   use the identifier `osx` or one that is prefixed with `osx-`. If such an
   entry is automatically discovered by the boot loader use `auto-osx` as
   identifier, or `auto-osx-` as prefix for the identifier, see above.

5. If a boot menu entry encapsulates the EFI shell program, it should use the
   identifier `efi-shell` (or when automatically discovered: `auto-efi-shell`,
   see above).

6. If a boot menu entry encapsulates a reboot into EFI firmware setup feature,
   it should use the identifier `reboot-to-firmware-setup` (or
   `auto-reboot-to-firmware-setup` in case it is automatically discovered).

## Links

[Boot Loader Specification](https://uapi-group.org/specifications/specs/boot_loader_specification)<br>
[Discoverable Partitions Specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification)<br>
[`systemd-boot(7)`](https://www.freedesktop.org/software/systemd/man/systemd-boot.html)<br>
[`bootctl(1)`](https://www.freedesktop.org/software/systemd/man/bootctl.html)<br>
[`systemd-gpt-auto-generator(8)`](https://www.freedesktop.org/software/systemd/man/systemd-gpt-auto-generator.html)
