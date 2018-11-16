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

* The EFI variable `LoaderConfigTimeout` contains the boot menu time-out
  currently in use. It may be modified both by the boot loader and by the
  host. The value should be formatted as numeric, NUL-terminated, decimal
  string, in UTF-16. The time is specified in µs.

* Similarly, the EFI variable `LoaderConfigTimeoutOneShot` contains a boot menu
  time-out for a single following boot. It is set by the OS in order to request
  display of the boot menu on the following boot. When set overrides
  `LoaderConfigTimeout`. It is removed automatically after being read by the
  boot loader, to ensure it only takes effect a single time. This value is
  formatted the same way as `LoaderConfigTimeout`. If set to `0` the boot menu
  time-out is turned off, and the menu is shown indefinitely.

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

* The EFI variable `LoaderFeatures` contains a 64bit unsigned integer with a
  number of flags bits that are set by the boot loader and passed to the OS and
  indicate the features the boot loader supports. Specifically, the following
  bits are defined:

  * `1 << 0` → The boot loader honours `LoaderConfigTimeout` when set.
  * `1 << 1` → The boot loader honours `LoaderConfigTimeoutOneShot` when set.
  * `1 << 2` → The boot loader honours `LoaderEntryDefault` when set.
  * `1 << 3` → The boot loader honours `LoaderEntryOneShot` when set.
  * `1 << 4` → The boot loader supports boot counting as described in [Automatic Boot Assessment](https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT).

If `LoaderTimeInitUSec` and `LoaderTimeExecUSec` are set, `systemd-analyze`
will include them in its boot-time analysis.  If `LoaderDevicePartUUID` is set,
systemd will mount the ESP that was used for the boot to `/boot`, but only if
that directory is empty, and only if no other file systems are mounted
there. The `systemctl reboot --boot-loader-entry=…` and `systemctl reboot
--boot-loader-menu=…` commands rely on the `LoaderFeatures` ,
`LoaderConfigTimeoutOneShot`, `LoaderEntries`, `LoaderEntryOneShot` variables.
