---
title: Known Environment Variables
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Known Environment Variables

A number of systemd components take additional runtime parameters via
environment variables. Many of these environment variables are not supported at
the same level as command line switches and other interfaces are: we don't
document them in the man pages and we make no stability guarantees for
them. While they generally are unlikely to be dropped any time soon again, we
do not want to guarantee that they stay around for good either.

Below is an (incomprehensive) list of the environment variables understood by
the various tools. Note that this list only covers environment variables not
documented in the proper man pages.

All tools:

* `$SYSTEMD_OFFLINE=[0|1]` — if set to `1`, then `systemctl` will refrain from
  talking to PID 1; this has the same effect as the historical detection of
  `chroot()`. Setting this variable to `0` instead has a similar effect as
  `$SYSTEMD_IN_CHROOT=0`; i.e. tools will try to communicate with PID 1
  even if a `chroot()` environment is detected. You almost certainly want to
  set this to `1` if you maintain a package build system or similar and are
  trying to use a modern container system and not plain `chroot()`.

* `$SYSTEMD_IN_CHROOT=0|1` — takes a boolean. If set, overrides chroot detection.
  This is particularly relevant for systemctl, as it will not alter its behaviour
  for `chroot()` environments if `SYSTEMD_IN_CHROOT=0`. Normally it refrains from
  talking to PID 1 in such a case; turning most operations such as `start` into
  no-ops. If that's what's explicitly desired, you might consider setting
  `$SYSTEMD_OFFLINE=1`.

* `$SYSTEMD_FIRST_BOOT=0|1` — if set, assume "first boot" condition to be false
  or true, instead of checking the flag file created by PID 1.

* `$SD_EVENT_PROFILE_DELAYS=1` — if set, the sd-event event loop implementation
  will print latency information at runtime.

* `$SYSTEMD_PROC_CMDLINE` — if set, the contents are used as the kernel command
  line instead of the actual one in `/proc/cmdline`. This is useful for
  debugging, in order to test generators and other code against specific kernel
  command lines.

* `$SYSTEMD_OS_RELEASE` — if set, use this path instead of `/etc/os-release` or
  `/usr/lib/os-release`. When operating under some root (e.g. `systemctl
  --root=…`), the path is prefixed with the root. Only useful for debugging.

* `$SYSTEMD_FSTAB` — if set, use this path instead of `/etc/fstab`. Only useful
  for debugging.

* `$SYSTEMD_SYSROOT_FSTAB` — if set, use this path instead of
  `/sysroot/etc/fstab`. Only useful for debugging `systemd-fstab-generator`.

* `$SYSTEMD_SYSFS_CHECK` — takes a boolean. If set, overrides sysfs container
  detection that ignores `/dev/` entries in fstab. Only useful for debugging
  `systemd-fstab-generator`.

* `$SYSTEMD_CRYPTTAB` — if set, use this path instead of `/etc/crypttab`. Only
  useful for debugging. Currently only supported by
  `systemd-cryptsetup-generator`.

* `$SYSTEMD_INTEGRITYTAB` — if set, use this path instead of
  `/etc/integritytab`. Only useful for debugging. Currently only supported by
  `systemd-integritysetup-generator`.

* `$SYSTEMD_VERITYTAB` — if set, use this path instead of
  `/etc/veritytab`. Only useful for debugging. Currently only supported by
  `systemd-veritysetup-generator`.

* `$SYSTEMD_DEFAULT_HOSTNAME` — override the compiled-in fallback hostname
  (relevant in particular for the system manager and `systemd-hostnamed`).
  Must be a valid hostname (either a single label or a FQDN).

* `$SYSTEMD_IN_INITRD` — takes a boolean. If set, overrides initrd detection.
  This is useful for debugging and testing initrd-only programs in the main
  system.

* `$SYSTEMD_BUS_TIMEOUT=SECS` — specifies the maximum time to wait for method call
  completion. If no time unit is specified, assumes seconds. The usual other units
  are understood, too (us, ms, s, min, h, d, w, month, y). If it is not set or set
  to 0, then the built-in default is used.

* `$SYSTEMD_MEMPOOL=0` — if set, the internal memory caching logic employed by
  hash tables is turned off, and libc `malloc()` is used for all allocations.

* `$SYSTEMD_UTF8=` — takes a boolean value, and overrides whether to generate
  non-ASCII special glyphs at various places (i.e. "→" instead of
  "->"). Usually this is determined automatically, based on `$LC_CTYPE`, but in
  scenarios where locale definitions are not installed it might make sense to
  override this check explicitly.

* `$SYSTEMD_EMOJI=0` — if set, tools such as `systemd-analyze security` will
  not output graphical smiley emojis, but ASCII alternatives instead. Note that
  this only controls use of Unicode emoji glyphs, and has no effect on other
  Unicode glyphs.

* `$RUNTIME_DIRECTORY` — various tools use this variable to locate the
  appropriate path under `/run/`. This variable is also set by the manager when
  `RuntimeDirectory=` is used, see systemd.exec(5).

* `$SYSTEMD_CRYPT_PREFIX` — if set configures the hash method prefix to use for
  UNIX `crypt()` when generating passwords. By default the system's "preferred
  method" is used, but this can be overridden with this environment variable.
  Takes a prefix such as `$6$` or `$y$`. (Note that this is only honoured on
  systems built with libxcrypt and is ignored on systems using glibc's
  original, internal `crypt()` implementation.)

* `$SYSTEMD_SECCOMP=0` — if set, seccomp filters will not be enforced, even if
  support for it is compiled in and available in the kernel.

* `$SYSTEMD_LOG_SECCOMP=1` — if set, system calls blocked by seccomp filtering,
  for example in `systemd-nspawn`, will be logged to the audit log, if the
  kernel supports this.

* `$SYSTEMD_ENABLE_LOG_CONTEXT` — if set, extra fields will always be logged to
  the journal instead of only when logging in debug mode.

* `$SYSTEMD_NETLINK_DEFAULT_TIMEOUT` — specifies the default timeout of waiting
  replies for netlink messages from the kernel. Defaults to 25 seconds.

* `$SYSTEMD_VERITY_SHARING=` — takes a boolean. If set, overrides whether
  dm-verity devices shall be shared between multiple components by using a
  stable `<ROOTHASH>-verity` device mapper name. The default for this depends
  on the subsystem in question. Usually,
  RootImage=/ExtensionImages=/MountImages= in unit files default to enabled,
  while other uses default to disabled for this.

`systemctl`:

* `$SYSTEMCTL_FORCE_BUS=1` — if set, do not connect to PID 1's private D-Bus
  listener, and instead always connect through the dbus-daemon D-bus broker.

* `$SYSTEMCTL_INSTALL_CLIENT_SIDE=1` — if set, enable or disable unit files on
  the client side, instead of asking PID 1 to do this.

* `$SYSTEMCTL_SKIP_AUTO_KEXEC=1` — if set, do not automatically kexec instead of
  reboot when a new kernel has been loaded.

* `$SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT=1` — if set, do not automatically soft-reboot
  instead of reboot when a new root file system has been loaded in
  `/run/nextroot/`.

* `SYSTEMD_PRESET_BYPASS=1` — If set, execution of `systemctl preset` and
  `systemctl preset-all` is skipped. This can be useful if either of these is
  invoked unconditionally as a child process by another tool, such as package
  managers running it in a postinstall script.

`systemd-nspawn`:

* `$SYSTEMD_NSPAWN_API_VFS_WRITABLE=1` — if set, make `/sys/`, `/proc/sys/`,
  and friends writable in the container. If set to "network", leave only
  `/proc/sys/net/` writable.

* `$SYSTEMD_NSPAWN_CONTAINER_SERVICE=…` — override the "service" name nspawn
  uses to register with machined. If unset defaults to "nspawn", but with this
  variable may be set to any other value.

* `$SYSTEMD_NSPAWN_USE_CGNS=0` — if set, do not use cgroup namespacing, even if
  it is available.

* `$SYSTEMD_NSPAWN_LOCK=0` — if set, do not lock container images when running.

* `$SYSTEMD_NSPAWN_TMPFS_TMP=0` — if set, do not overmount `/tmp/` in the
  container with a tmpfs, but leave the directory from the image in place.

* `$SYSTEMD_NSPAWN_CHECK_OS_RELEASE=0` — if set, do not fail when trying to
  boot an OS tree without an os-release file (useful when trying to boot a
  container with empty `/etc/` and bind-mounted `/usr/`)

* `$SYSTEMD_SUPPRESS_SYNC=1` — if set, all disk synchronization syscalls are
  blocked to the container payload (e.g. `sync()`, `fsync()`, `syncfs()`, …)
  and the `O_SYNC`/`O_DSYNC` flags are made unavailable to `open()` and
  friends. This is equivalent to passing `--suppress-sync=yes` on the
  `systemd-nspawn` command line.

* `$SYSTEMD_NSPAWN_NETWORK_MAC=...` — if set, allows users to set a specific MAC
  address for a container, ensuring that it uses the provided value instead of
  generating a random one. It is effective when used with `--network-veth`. The
  expected format is six groups of two hexadecimal digits separated by colons,
  e.g. `SYSTEMD_NSPAWN_NETWORK_MAC=12:34:56:78:90:AB`

`systemd-vmspawn`:

* `$SYSTEMD_VMSPAWN_NETWORK_MAC=...` — if set, allows users to set a specific MAC
  address for a VM, ensuring that it uses the provided value instead of
  generating a random one. It is effective when used with `--network-tap`. The
  expected format is six groups of two hexadecimal digits separated by colons,
  e.g. `SYSTEMD_VMSPAWN_NETWORK_MAC=12:34:56:78:90:AB`

* `$SYSTEMD_VMSPAWN_QEMU_EXTRA=…` – may contain additional command line
  arguments to append the qemu command line.

`systemd-logind`:

* `$SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK=1` — if set, report that
  hibernation is available even if the swap devices do not provide enough room
  for it.

* `$SYSTEMD_REBOOT_TO_FIRMWARE_SETUP` — if set, overrides `systemd-logind`'s
  built-in EFI logic of requesting a reboot into the firmware. Takes a boolean.
  If set to false, the functionality is turned off entirely. If set to true,
  instead of requesting a reboot into the firmware setup UI through EFI a file,
  `/run/systemd/reboot-to-firmware-setup` is created whenever this is
  requested. This file may be checked for by services run during system
  shutdown in order to request the appropriate operation from the firmware in
  an alternative fashion.

* `$SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU` — similar to the above, allows
  overriding of `systemd-logind`'s built-in EFI logic of requesting a reboot
  into the boot loader menu. Takes a boolean. If set to false, the
  functionality is turned off entirely. If set to true, instead of requesting a
  reboot into the boot loader menu through EFI, the file
  `/run/systemd/reboot-to-boot-loader-menu` is created whenever this is
  requested. The file contains the requested boot loader menu timeout in µs,
  formatted in ASCII decimals, or zero in case no timeout is requested. This
  file may be checked for by services run during system shutdown in order to
  request the appropriate operation from the boot loader in an alternative
  fashion.

* `$SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY` — similar to the above, allows
  overriding of `systemd-logind`'s built-in EFI logic of requesting a reboot
  into a specific boot loader entry. Takes a boolean. If set to false, the
  functionality is turned off entirely. If set to true, instead of requesting a
  reboot into a specific boot loader entry through EFI, the file
  `/run/systemd/reboot-to-boot-loader-entry` is created whenever this is
  requested. The file contains the requested boot loader entry identifier. This
  file may be checked for by services run during system shutdown in order to
  request the appropriate operation from the boot loader in an alternative
  fashion. Note that by default only boot loader entries which follow the
  [UAPI.1 Boot Loader Specification](https://uapi-group.org/specifications/specs/boot_loader_specification)
  and are placed in the ESP or the Extended Boot Loader partition may be
  selected this way. However, if a directory `/run/boot-loader-entries/`
  exists, the entries are loaded from there instead. The directory should
  contain the usual directory hierarchy mandated by the Boot Loader
  Specification, i.e. the entry drop-ins should be placed in
  `/run/boot-loader-entries/loader/entries/*.conf`, and the files referenced by
  the drop-ins (including the kernels and initrds) somewhere else below
  `/run/boot-loader-entries/`. Note that all these files may be (and are
  supposed to be) symlinks. `systemd-logind` will load these files on-demand,
  these files can hence be updated (ideally atomically) whenever the boot
  loader configuration changes. A foreign boot loader installer script should
  hence synthesize drop-in snippets and symlinks for all boot entries at boot
  or whenever they change if it wants to integrate with `systemd-logind`'s
  APIs.

`systemd-udevd` and sd-device library:

* `$NET_NAMING_SCHEME=` — if set, takes a network naming scheme (i.e. one of
  "v238", "v239", "v240"…, or the special value "latest") as parameter. If
  specified udev's `net_id` builtin will follow the specified naming scheme
  when determining stable network interface names. This may be used to revert
  to naming schemes of older udev versions, in order to provide more stable
  naming across updates. This environment variable takes precedence over the
  kernel command line option `net.naming_scheme=`, except if the value is
  prefixed with `:` in which case the kernel command line option takes
  precedence, if it is specified as well.

* `$SYSTEMD_DEVICE_VERIFY_SYSFS` — if set to "0", disables verification that
  devices sysfs path are actually backed by sysfs. Relaxing this verification
  is useful for testing purposes.

* `$SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC=` — Specifies an extra timespan that the
  udev manager process waits for a worker process kills slow programs specified
  by IMPORT{program}=, PROGRAM=, or RUN=, and finalizes the processing event.
  If the worker process cannot finalize the event within the specified timespan,
  the worker process is killed by the manager process. Defaults to 10 seconds,
  maximum allowed is 5 hours.

`udevadm` and `systemd-hwdb`:

* `SYSTEMD_HWDB_UPDATE_BYPASS=` — If set to "1", execution of hwdb updates is skipped
  when `udevadm hwdb --update` or `systemd-hwdb update` are invoked. This can
  be useful if either of these tools are invoked unconditionally as a child
  process by another tool, such as package managers running either of these
  tools in a postinstall script.

`nss-systemd`:

* `$SYSTEMD_NSS_BYPASS_SYNTHETIC=1` — if set, `nss-systemd` won't synthesize
  user/group records for the `root` and `nobody` users if they are missing from
  `/etc/passwd`.

* `$SYSTEMD_NSS_DYNAMIC_BYPASS=1` — if set, `nss-systemd` won't return
  user/group records for dynamically registered service users (i.e. users
  registered through `DynamicUser=1`).

* `$SYSTEMD_NSS_LOG_LEVEL=<level>` — If set, sets the log level for `nss-systemd`
  and other NSS plugins specifically. Takes priority over `$SYSTEMD_LOG_LEVEL`.

`systemd-timedated`:

* `$SYSTEMD_TIMEDATED_NTP_SERVICES=…` — colon-separated list of unit names of
  NTP client services. If set, `timedatectl set-ntp on` enables and starts the
  first existing unit listed in the environment variable, and
  `timedatectl set-ntp off` disables and stops all listed units.

* `$SYSTEMD_ETC_ADJTIME` - override the path to the hardware clock settings
  file. The default is `/etc/adjtime`.

`systemd-sulogin-shell`:

* `$SYSTEMD_SULOGIN_FORCE=1` — This skips asking for the root password if the
  root password is not available (such as when the root account is locked).
  See `sulogin(8)` for more details.

`bootctl` and other tools that access the EFI System Partition (ESP):

* `$SYSTEMD_RELAX_ESP_CHECKS=1` — if set, the ESP validation checks are
  relaxed. Specifically, validation checks that ensure the specified ESP path
  is a FAT file system are turned off, as are checks that the path is located
  on a GPT partition with the correct type UUID.

* `$SYSTEMD_ESP_PATH=…` — override the path to the EFI System Partition. This
  may be used to override ESP path auto detection, and redirect any accesses to
  the ESP to the specified directory. Note that unlike with `bootctl`'s
  `--path=` switch only very superficial validation of the specified path is
  done when this environment variable is used.

* `$KERNEL_INSTALL_CONF_ROOT=…` — override the built in default configuration
  directory /etc/kernel/ to read files like entry-token and install.conf from.

`systemd` itself:

* `$SYSTEMD_ACTIVATION_UNIT` — set for all NSS and PAM module invocations that
  are done by the service manager on behalf of a specific unit, in child
  processes that are later (after execve()) going to become unit
  processes. Contains the full unit name (e.g. "foobar.service"). NSS and PAM
  modules can use this information to determine in which context and on whose
  behalf they are being called, which may be useful to avoid deadlocks, for
  example to bypass IPC calls to the very service that is about to be
  started. Note that NSS and PAM modules should be careful to only rely on this
  data when invoked privileged, or possibly only when getppid() returns 1, as
  setting environment variables is of course possible in any even unprivileged
  contexts.

* `$SYSTEMD_ACTIVATION_SCOPE` — closely related to `$SYSTEMD_ACTIVATION_UNIT`,
  it is either set to `system` or `user` depending on whether the NSS/PAM
  module is called by systemd in `--system` or `--user` mode.

* `$SYSTEMD_SUPPORT_DEVICE`, `$SYSTEMD_SUPPORT_MOUNT`, `$SYSTEMD_SUPPORT_SWAP` -
  can be set to `0` to mark respective unit type as unsupported. Generally,
  having less units saves system resources so these options might be useful
  for cases where we don't need to track given unit type, e.g. `--user` manager
  often doesn't need to deal with device or swap units because they are
  handled by the `--system` manager (PID 1). Note that setting certain unit
  type as unsupported might not prevent loading some units of that type if they
  are referenced by other units of another supported type.

* `$SYSTEMD_DEFAULT_MOUNT_RATE_LIMIT_BURST` — can be set to override the mount
  units burst rate limit for parsing `/proc/self/mountinfo`. On a system with
  few resources but many mounts the rate limit may be hit, which will cause the
  processing of mount units to stall. The burst limit may be adjusted when the
  default is not appropriate for a given system. Defaults to `5`, accepts
  positive integers.

* `$SYSTEMD_DEFAULT_MOUNT_RATE_LIMIT_INTERVAL_SEC` — can be set to override the
  mount units interval rate limit for parsing `/proc/self/mountinfo`. Similar
  to `$SYSTEMD_DEFAULT_MOUNT_RATE_LIMIT_BURST`, the interval limit maybe
  adjusted when the default is not appropriate for a given system. The default
  value is 1, the default application time unit is second, and the time unit
  can be overridden as usual by specifying it explicitly, see the
  systemd.time(7) man page.

`systemd-remount-fs`:

* `$SYSTEMD_REMOUNT_ROOT_RW=1` — if set and no entry for the root directory
  exists in `/etc/fstab` (this file always takes precedence), then the root
  directory is remounted writable. This is primarily used by
  `systemd-gpt-auto-generator` to ensure the root partition is mounted writable
  in accordance to the GPT partition flags.

`systemd-firstboot`, `localectl`, and `systemd-localed`:

* `$SYSTEMD_LIST_NON_UTF8_LOCALES=1` — if set, non-UTF-8 locales are listed among
  the installed ones. By default non-UTF-8 locales are suppressed from the
  selection, since we are living in the 21st century.

* `$SYSTEMD_KEYMAP_DIRECTORIES=` — takes a colon (`:`) separated list of keymap
  directories. The directories must be absolute and normalized. If unset, the
  default keymap directories (`/usr/share/keymaps/`, `/usr/share/kbd/keymaps/`,
  and `/usr/lib/kbd/keymaps/`) will be used.

* `$SYSTEMD_XKB_DIRECTORY=` — The directory must be absolute and normalized. If
  unset, the default XKB directory (`/usr/share/X11/xkb/`) will be used.

* `$SYSTEMD_LOCALE_DIRECTORY=` — The directory must be absolute and normalized.
  If unset, the default locale directory of the C library (`/usr/lib/locale/`
  for glibc and `/usr/share/i18n/locales/musl/` for musl) will be used.

`systemd-resolved`:

* `$SYSTEMD_RESOLVED_SYNTHESIZE_HOSTNAME` — if set to "0", `systemd-resolved`
  won't synthesize A/AAAA/PTR RRs for the system hostname on either regular nor
  reverse lookups.

`systemd-sysext`:

* `$SYSTEMD_SYSEXT_HIERARCHIES` — this variable may be used to override which
  hierarchies are managed by `systemd-sysext`. By default only `/usr/` and
  `/opt/` are managed, and directories may be added or removed to that list by
  setting this environment variable to a colon-separated list of absolute
  paths. Only "real" file systems and directories that only contain "real" file
  systems as submounts should be used. Do not specify API file systems such as
  `/proc/` or `/sys/` here, or hierarchies that have them as submounts. In
  particular, do not specify the root directory `/` here. Similarly,
  `$SYSTEMD_CONFEXT_HIERARCHIES` works for confext images and supports the
  systemd-confext multi-call functionality of sysext.

* `$SYSTEMD_SYSEXT_MUTABLE_MODE` — this variable may be used to override the
  default mutability mode for hierarchies managed by `systemd-sysext`. It takes
  the same values the `--mutable=` command line switch does. Note that the
  command line still overrides the effect of the environment
  variable. Similarly, `$SYSTEMD_CONFEXT_MUTABLE_MODE` works for confext images
  and supports the systemd-confext multi-call functionality of sysext.

* `$SYSTEMD_SYSEXT_OVERLAYFS_MOUNT_OPTIONS` — this variable may be used to
  override the overlayfs mount options applied for hierarchies managed by
  `systemd-sysext`. Similarly, `$SYSTEMD_CONFEXT_OVERLAYFS_MOUNT_OPTIONS` works
  for confext images and supports the systemd-confext multi-call functionality
  of sysext. Read-only hierarchies have no mount options added by
  default. Mutable hierarchies have the following mount options added by
  default: `redirect_dir=on,noatime,metacopy=off,index=off`.

`systemd-tmpfiles`:

* `$SYSTEMD_TMPFILES_FORCE_SUBVOL` — if unset, `v`/`q`/`Q` lines will create
  subvolumes only if the OS itself is installed into a subvolume. If set to `1`
  (or another value interpreted as true), these lines will always create
  subvolumes if the backing filesystem supports them. If set to `0`, these
  lines will always create directories.

* `SYSTEMD_TMPFILES_BYPASS=1` — If set, execution of `systemd-tmpfiles` is
  skipped. This can be useful if `systemd-tmpfiles` is invoked unconditionally
  as a child process by another tool, such as package managers running it in a
  postinstall script.

`systemd-sysusers`:

* `$SOURCE_DATE_EPOCH` — if unset, the field of the date of last password change
  in `/etc/shadow` will be the number of days from Jan 1, 1970 00:00 UTC until
  today. If `$SOURCE_DATE_EPOCH` is set to a valid UNIX epoch value in seconds,
  then the field will be the number of days until that time instead. This is to
  support creating bit-by-bit reproducible system images by choosing a
  reproducible value for the field of the date of last password change in
  `/etc/shadow`. See: https://reproducible-builds.org/specs/source-date-epoch/

* `SYSTEMD_SYSUSERS_BYPASS=1` — If set, execution of `systemd-sysusers` is
  skipped. This can be useful if `systemd-sysusers` is invoked unconditionally
  as a child process by another tool, such as package managers running it in a
  postinstall script.

systemd tests:

* `$SYSTEMD_TEST_DATA` — override the location of test data. This is useful if
  a test executable is moved to an arbitrary location.

* `$SYSTEMD_TEST_NSS_BUFSIZE` — size of scratch buffers for "reentrant"
  functions exported by the nss modules.

* `$TESTFUNCS` – takes a colon separated list of test functions to invoke,
  causes all non-matching test functions to be skipped. Only applies to tests
  using our regular test boilerplate.

* `$SYSTEMD_ASSERT_RETURN_IS_CRITICAL` — Takes a boolean to control if
  `assert_return()` and friends call `abort()`.

fuzzers:

* `$SYSTEMD_FUZZ_OUTPUT` — A boolean that specifies whether to write output to
  stdout. Setting to true is useful in manual invocations, since all output is
  suppressed by default.

* `$SYSTEMD_FUZZ_RUNS` — The number of times execution should be repeated in
  manual invocations.

Note that it may be also useful to set `$SYSTEMD_LOG_LEVEL`, since all logging
is suppressed by default.

`systemd-importd`:

* `$SYSTEMD_IMPORT_BTRFS_SUBVOL` — takes a boolean, which controls whether to
  prefer creating btrfs subvolumes over plain directories for machine
  images. Has no effect on non-btrfs file systems where subvolumes are not
  available anyway. If not set, defaults to true.

* `$SYSTEMD_IMPORT_BTRFS_QUOTA` — takes a boolean, which controls whether to set
  up quota automatically for created btrfs subvolumes for machine images. If
  not set, defaults to true. Has no effect if machines are placed in regular
  directories, because btrfs subvolumes are not supported or disabled. If
  enabled, the quota group of the subvolume is automatically added to a
  combined quota group for all such machine subvolumes.

* `$SYSTEMD_IMPORT_SYNC` — takes a boolean, which controls whether to
  synchronize images to disk after installing them, before completing the
  operation. If not set, defaults to true. If disabled installation of images
  will be quicker, but not as safe.

`systemd-dissect`, `systemd-nspawn` and all other tools that may operate on
disk images with `--image=` or similar:

* `$SYSTEMD_DISSECT_VERITY_SIDECAR` — takes a boolean, which controls whether to
  load "sidecar" Verity metadata files. If enabled (which is the default),
  whenever a disk image is used, a set of files with the `.roothash`,
  `.usrhash`, `.roothash.p7s`, `.usrhash.p7s`, `.verity` suffixes are searched
  adjacent to disk image file, containing the Verity root hashes, their
  signatures or the Verity data itself. If disabled this automatic discovery of
  Verity metadata files is turned off.

* `$SYSTEMD_DISSECT_VERITY_EMBEDDED` — takes a boolean, which controls whether
  to load the embedded Verity signature data. If enabled (which is the
  default), Verity root hash information and a suitable signature is
  automatically acquired from a signature partition, following the
  [UAPI.2 Discoverable Partitions Specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification).
  If disabled any such partition is ignored. Note that this only disables
  discovery of the root hash and its signature, the Verity data partition
  itself is still searched in the GPT image.

* `$SYSTEMD_DISSECT_VERITY_SIGNATURE` — takes a boolean, which controls whether
  to validate the signature of the Verity root hash if available. If enabled
  (which is the default), the signature of suitable disk images is validated
  against any of the certificates in `/etc/verity.d/*.crt` (and similar
  directories in `/usr/lib/`, `/run`, …) or passed to the kernel for validation
  against its built-in certificates.

* `$SYSTEMD_DISSECT_VERITY_TIMEOUT_SEC=sec` — takes a timespan, which controls
  the timeout waiting for the image to be configured. Defaults to 100 msec.

* `$SYSTEMD_DISSECT_FILE_SYSTEMS=` — takes a colon-separated list of file
  systems that may be mounted for automatically dissected disk images. If not
  specified defaults to something like: `ext4:btrfs:xfs:vfat:erofs:squashfs`

* `$SYSTEMD_DISSECT_FSTYPE_<DESIGNATOR>=` – overrides the file system time to
  use when mounting the partition of the indicated designator. The
  `<DESIGNATOR>` string shall be one of `ROOT`, `USR`, `HOME`, `SRV`, `ESP`,
  `XBOOTLDR`, `TMP`, `VAR` as per the [UAPI.2 Discoverable Partitions
  Specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/). If
  unspecified the image dissection logic will automatically probe the file
  system type (subject to `$SYSTEMD_DISSECT_FILE_SYSTEMS`, see above), except
  for ESP and XBOOTLDR where the file system type is set to VFAT.

* `$SYSTEMD_LOOP_DIRECT_IO` – takes a boolean, which controls whether to enable
  `LO_FLAGS_DIRECT_IO` (i.e. direct IO + asynchronous IO) on loopback block
  devices when opening them. Defaults to on, set this to "0" to disable this
  feature.

* `$SYSTEMD_ALLOW_USERSPACE_VERITY` — takes a boolean, which controls whether
  to consider the userspace Verity public key store in `/etc/verity.d/` (and
  related directories) to authenticate signatures on Verity hashes of disk
  images. Defaults to true, i.e. userspace signature validation is allowed. If
  false, authentication can be done only via the kernel's internal keyring.

* `$SYSTEMD_DISSECT_VERITY_GUESS` – takes a boolean. Controls whether to guess
  the Verity root hash from the partition UUIDs of a suitable pair of data
  partition and matching Verity partition: the UUIDs two are simply joined and
  used as root hash, in accordance with the recommendations in [UAPI.2
  Discoverable Partitions
  Specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification). Defaults
  to true.

`systemd-cryptsetup`:

* `$SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE` – takes a boolean, which controls
  whether to use the libcryptsetup "token" plugin module logic even when
  activating via FIDO2, PKCS#11, TPM2, i.e. mechanisms natively supported by
  `systemd-cryptsetup`. Defaults to enabled.

* `$SYSTEMD_CRYPTSETUP_TOKEN_PATH` – takes a path to a directory in the file
  system. If specified overrides where libcryptsetup will look for token
  modules (.so). This is useful for debugging token modules: set this
  environment variable to the build directory and you are set. This variable
  is only supported when systemd is compiled in developer mode.

Various tools that read passwords from the TTY, such as `systemd-cryptenroll`,
`systemd-dissect` and `homectl`:

* `$PASSWORD` — takes a string: the literal password to use. If this
  environment variable is set it is used as password instead of prompting the
  user interactively. This exists primarily for debugging and testing
  purposes. Do not use this for production code paths, since environment
  variables are typically inherited down the process tree without restrictions
  and should thus not be used for secrets.

* `$NEWPASSWORD` — similar to `$PASSWORD` above, but is used when both a
  current and a future password are required, for example if the password is to
  be changed. In that case `$PASSWORD` shall carry the current (i.e. old)
  password and `$NEWPASSWORD` the new.

`systemd-homed`:

* `$SYSTEMD_HOME_ROOT` – defines an absolute path where to look for home
  directories/images. When unspecified defaults to `/home/`. This is useful for
  debugging purposes in order to run a secondary `systemd-homed` instance that
  operates on a different directory where home directories/images are placed.

* `$SYSTEMD_HOME_RECORD_DIR` – defines an absolute path where to look for
  fixated home records kept on the host. When unspecified defaults to
  `/var/lib/systemd/home/`. Similar to `$SYSTEMD_HOME_ROOT` this is useful for
  debugging purposes, in order to run a secondary `systemd-homed` instance that
  operates on a record database entirely separate from the host's.

* `$SYSTEMD_HOME_DEBUG_SUFFIX` – takes a short string that is suffixed to
  `systemd-homed`'s D-Bus and Varlink service names/sockets. This is also
  understood by `homectl`. This too is useful for running an additional copy of
  `systemd-homed` that doesn't interfere with the host's main one.

* `$SYSTEMD_HOMEWORK_PATH` – configures the path to the `systemd-homework`
  binary to invoke. If not specified defaults to
  `/usr/lib/systemd/systemd-homework`.

  Combining these four environment variables is pretty useful when
  debugging/developing `systemd-homed`:
```sh
SYSTEMD_HOME_DEBUG_SUFFIX=foo \
      SYSTEMD_HOMEWORK_PATH=/home/lennart/projects/systemd/build/systemd-homework \
      SYSTEMD_HOME_ROOT=/home.foo/ \
      SYSTEMD_HOME_RECORD_DIR=/var/lib/systemd/home.foo/ \
      /home/lennart/projects/systemd/build/systemd-homed
```

* `$SYSTEMD_HOME_MOUNT_OPTIONS_BTRFS`, `$SYSTEMD_HOME_MOUNT_OPTIONS_EXT4`,
  `$SYSTEMD_HOME_MOUNT_OPTIONS_XFS` – configure the default mount options to
  use for LUKS home directories, overriding the built-in default mount
  options. There's one variable for each of the supported file systems for the
  LUKS home directory backend.

* `$SYSTEMD_HOME_MKFS_OPTIONS_BTRFS`, `$SYSTEMD_HOME_MKFS_OPTIONS_EXT4`,
  `$SYSTEMD_HOME_MKFS_OPTIONS_XFS` – configure additional arguments to use for
  `mkfs` when formatting LUKS home directories. There's one variable for each
  of the supported file systems for the LUKS home directory backend.

* `$SYSTEMD_HOME_LOCK_FREEZE_SESSION` - Takes a boolean. When false, the user's
  session will not be frozen when the home directory is locked. Note that the kernel
  may still freeze any task that tries to access data from the user's locked home
  directory. This can lead to data loss, security leaks, or other undesired behavior
  caused by parts of the session becoming unresponsive due to disk I/O while other
  parts of the session continue running. Thus, we highly recommend that this variable
  isn't used unless necessary. Defaults to true.

`homectl`:

* `$SYSTEMD_HOME_FIRSTBOOT_OVERRIDE` – if set to "1" will make `homectl
  firstboot --prompt-new-user` interactively ask for user creation, even if
  there already exists at least one regular user on the system. If set to "0"
  will make the tool skip any such query.

* `$SYSTEMD_HOME_DRY_RUN` – if set to "1" will make `homectl create` and
  `homectl update` operate in a "dry-run" mode: the new user record is
  assembled, and displayed in JSON format, but not actually passed to
  `systemd-homed` for execution of the operation.

`kernel-install`:

* `$KERNEL_INSTALL_BYPASS` – If set to "1", execution of kernel-install is skipped
  when kernel-install is invoked. This can be useful if kernel-install is invoked
  unconditionally as a child process by another tool, such as package managers
  running kernel-install in a postinstall script.

`systemd-journald`, `journalctl`:

* `$SYSTEMD_JOURNAL_COMPACT` – Takes a boolean. If enabled, journal files are written
  in a more compact format that reduces the amount of disk space required by the
  journal. Note that journal files in compact mode are limited to 4G to allow use of
  32-bit offsets. Enabled by default.

* `$SYSTEMD_JOURNAL_COMPRESS` – Takes a boolean, or one of the compression
  algorithms "XZ", "LZ4", and "ZSTD". If enabled, the default compression
  algorithm set at compile time will be used when opening a new journal file.
  If disabled, the journal file compression will be disabled. Note that the
  compression mode of existing journal files are not changed. To make the
  specified algorithm takes an effect immediately, you need to explicitly run
  `journalctl --rotate`.

* `$SYSTEMD_JOURNAL_FD_SIZE_MAX` – Takes a size with the usual suffixes (K, M, ...) in
  string format. Overrides the default maximum allowed size for a file-descriptor
  based input record to be stored in the journal.

* `$SYSTEMD_CATALOG` – path to the compiled catalog database file to use for
  `journalctl -x`, `journalctl --update-catalog`, `journalctl --list-catalog`
  and related calls.

* `$SYSTEMD_CATALOG_SOURCES` – path to the catalog database input source
  directory to use for `journalctl --update-catalog`.

`systemd-pcrextend`, `systemd-cryptsetup`:

* `$SYSTEMD_FORCE_MEASURE=1` — If set, force measuring of resources (which are
  marked for measurement) even if not booted on a kernel equipped with
  systemd-stub. Normally, requested measurement of resources is conditionalized
  on kernels that have booted with `systemd-stub`. With this environment
  variable the test for that my be bypassed, for testing purposes.

`systemd-repart`:

* `$SYSTEMD_REPART_MKFS_OPTIONS_<FSTYPE>` – configure additional arguments to use for
  `mkfs` when formatting partition file systems. There's one variable for each
  of the supported file systems.

* `$SYSTEMD_REPART_OVERRIDE_FSTYPE` – if set the value will override the file
  system type specified in Format= lines in partition definition files.
  Additionally, the filesystem for all partitions with a specific designator can
  be overridden via a correspondingly named environment variable. For example,
  to override the filesystem type for all partitions with `Type=root`, you can
  set `SYSTEMD_REPART_OVERRIDE_FSTYPE_ROOT=ext4`.

`systemd-nspawn`, `systemd-networkd`:

* `$SYSTEMD_FIREWALL_BACKEND` – takes a string, either `iptables` or
  `nftables`. Selects the firewall backend to use. If not specified tries to
  use `nftables` and falls back to `iptables` if that's not available.

`systemd-networkd`:

* `$SYSTEMD_NETWORK_PERSISTENT_STORAGE_READY` – takes a boolean. If true,
  systemd-networkd tries to open the persistent storage on start. To make this
  work, ProtectSystem=strict in systemd-networkd.service needs to be downgraded
  or disabled.

* `$SYSTEMD_LLDP_SEND_MACHINE_ID` - takes a boolean, If true, systemd-networkd
  sends machine ID as chassis ID through LLDP protocol.

`systemd-storagetm`:

* `$SYSTEMD_NVME_MODEL`, `$SYSTEMD_NVME_FIRMWARE`, `$SYSTEMD_NVME_SERIAL`,
  `$SYSTEMD_NVME_UUID` – these take a model string, firmware version string,
  serial number string, and UUID formatted as string. If specified these
  override the defaults exposed on the NVME subsystem and namespace, which are
  derived from the underlying block device and system identity. Do not set the
  latter two via the environment variable unless `systemd-storagetm` is invoked
  to expose a single device only, since those identifiers better should be kept
  unique.

`systemd-pcrlock`, `systemd-pcrextend`:

* `$SYSTEMD_MEASURE_LOG_USERSPACE` – the path to the `tpm2-measure.log` file
  (containing userspace measurement data) to read. This allows overriding the
  default of `/run/log/systemd/tpm2-measure.log`.

* `$SYSTEMD_MEASURE_LOG_FIRMWARE` – the path to the `binary_bios_measurements`
  file (containing firmware measurement data) to read. This allows overriding
  the default of `/sys/kernel/security/tpm0/binary_bios_measurements`.

`systemd-sleep`:

* `$SYSTEMD_SLEEP_FREEZE_USER_SESSIONS` - Takes a boolean. When true (the default),
  `user.slice` will be frozen during sleep. When false it will not be. We recommend
  against using this variable, because it can lead to undesired behavior, especially
  for systems that use home directory encryption and for
  `systemd-suspend-then-hibernate.service`.

Tools using the Varlink protocol (such as `varlinkctl`) or sd-bus (such as
`busctl`):

* `$SYSTEMD_SSH` – the ssh binary to invoke when the `ssh:` transport is
  used. May be a filename (which is searched for in `$PATH`) or absolute path.

* `$SYSTEMD_VARLINK_LISTEN` – interpreted by some tools that provide a Varlink
  service. Takes a file system path: if specified the tool will listen on an
  `AF_UNIX` stream socket on the specified path in addition to whatever else it
  would listen on. If set to "-" the tool will turn stdin/stdout into a Varlink
  connection.

* `$SYSTEMD_VARLINK_BRIDGES_DIR` – overrides the default `$LIBEXEC/varlink-bridges/`
  path when looking up custom scheme bridge helper binaries.

`systemd-mountfsd`:

* `$SYSTEMD_MOUNTFSD_TRUSTED_DIRECTORIES` – takes a boolean argument. If true
  disk images from the usual disk image directories (`/var/lib/machines/`,
  `/var/lib/confexts/`, …) will be considered "trusted", i.e. are validated
  with a more relaxed image policy (typically not requiring Verity signature
  checking) than those from other directories (where Verity signature checks
  are mandatory). If false all images are treated the same, regardless if
  placed in the usual disk image directories or elsewhere. If not set defaults
  to a compile time setting.

* `$SYSTEMD_MOUNTFSD_IMAGE_POLICY_TRUSTED`,
  `$SYSTEMD_MOUNTFSD_IMAGE_POLICY_UNTRUSTED` – the default image policy to
  apply to trusted and untrusted disk images. An image is considered trusted if
  placed in a trusted disk image directory (see above), or if suitable polkit
  authentication was acquired. See `systemd.image-policy(7)` for the valid
  syntax for image policy strings.

`systemd-run`, `run0`, `systemd-nspawn`, `systemd-vmspawn`:

* `$SYSTEMD_TINT_BACKGROUND` – Takes a boolean. When false the automatic and
  explicit tinting of the background (via `--background=`) for containers, VMs,
  `systemd-pty-forward` and interactive  `systemd-run` and `run0` invocations is
  turned off.

* `$SYSTEMD_ADJUST_TERMINAL_TITLE` – Takes a boolean. When false the terminal
  window title will not be updated for interactive invocation of the tools
  mentioned above.

`systemd-hostnamed`, `systemd-importd`, `systemd-localed`, `systemd-machined`,
`systemd-portabled`, `systemd-timedated`:

* `SYSTEMD_EXIT_ON_IDLE` – Takes a boolean. When false, the exit-on-idle logic
  of these services is disabled, making it easier to debug them.

`systemd-ask-password`:

* `$SYSTEMD_ASK_PASSWORD_KEYRING_TIMEOUT_SEC` - takes a timespan, which controls
  the expiration time of keys stored in the kernel keyring by `systemd-ask-password`.
  If unset, the default expiration of 150 seconds is used. If set to `0`, keys are
  not cached in the kernel keyring. If set to `infinity`, keys are cached without an
  expiration time in the kernel keyring.

* `SYSTEMD_ASK_PASSWORD_KEYRING_TYPE` - takes a keyring ID or one of `thread`,
  `process`, `session`, `user`, `user-session`, or `group`. Controls the kernel
  keyring in which `systemd-ask-password` caches the queried password. Defaults
  to `user`.

`systemd-tpm2-clear`:

* `SYSTEMD_TPM2_ALLOW_CLEAR` – takes a boolean. Overrides the effect of the
  `systemd.factory_reset=` kernel command line option: if set to false,
  requesting a TPM clearing is skipped, and the command immediately exits
  successfully.

`systemd-timedated`, `systemd-firstboot`, `systemd`:

* `$SYSTEMD_ETC_LOCALTIME` - override the path to the timezone symlink. The
  default is `/etc/localtime`. The directory of the path should exist and not
  be removed.

`systemd-hostnamed`, `systemd-firstboot`:

* `$SYSTEMD_ETC_HOSTNAME` - override the path to local system name
  configuration file. The default is `/etc/hostname`.

* `$SYSTEMD_ETC_MACHINE_INFO` - override the path to the machine metadata file. The
  default is `/etc/machine-info`.

`systemd-localed`, `systemd-firstboot`:

* `$SYSTEMD_ETC_LOCALE_CONF` - override the path to the system-wide locale
  configuration file. The default is `/etc/locale.conf`.

* `$SYSTEMD_ETC_VCONSOLE_CONF` - override the path to the virtual console
  configuration file. The default is `/etc/vconsole.conf`.

`systemd-modules-load`:

* `$SYSTEMD_MODULES_LOAD_NUM_THREADS` - takes a number, which controls the
  overall number of threads used to load modules by `systemd-modules-load`.
  If unset, the default number of threads is equal to the number of online CPUs,
  with a maximum of 16. If set to `0`, multi-threaded loading is disabled.

`systemd-sysupdate`:

* `$SYSTEMD_SYSUPDATE_VERIFY_FRESHNESS` – takes a boolean. If false the
  'freshness' check via `BEST-BEFORE-YYYY-MM-DD` files in `SHA256SUMS` manifest
  files is disabled, and updating from outdated manifests will not result in an
  error.
