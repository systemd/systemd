---
title: Known Environment Variables
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

* `$SYSTEMD_OFFLINE=[0|1]` — if set to `1`, then `systemctl` will
  refrain from talking to PID 1; this has the same effect as the historical
  detection of `chroot()`.  Setting this variable to `0` instead has a similar
  effect as `SYSTEMD_IGNORE_CHROOT=1`; i.e. tools will try to
  communicate with PID 1 even if a `chroot()` environment is detected.
  You almost certainly want to set this to `1` if you maintain a package build system
  or similar and are trying to use a modern container system and not plain
  `chroot()`.

* `$SYSTEMD_IGNORE_CHROOT=1` — if set, don't check whether being invoked in a
  `chroot()` environment. This is particularly relevant for systemctl, as it
  will not alter its behaviour for `chroot()` environments if set.  Normally it
  refrains from talking to PID 1 in such a case; turning most operations such
  as `start` into no-ops.  If that's what's explicitly desired, you might
  consider setting `SYSTEMD_OFFLINE=1`.

* `$SD_EVENT_PROFILE_DELAYS=1` — if set, the sd-event event loop implementation
  will print latency information at runtime.

* `$SYSTEMD_PROC_CMDLINE` — if set, may contain a string that is used as kernel
  command line instead of the actual one readable from /proc/cmdline. This is
  useful for debugging, in order to test generators and other code against
  specific kernel command lines.

* `$SYSTEMD_IN_INITRD` — takes a boolean. If set, overrides initrd detection.
  This is useful for debugging and testing initrd-only programs in the main
  system.

* `$SYSTEMD_BUS_TIMEOUT=SECS` — specifies the maximum time to wait for method call
  completion. If no time unit is specified, assumes seconds. The usual other units
  are understood, too (us, ms, s, min, h, d, w, month, y). If it is not set or set
  to 0, then the built-in default is used.

* `$SYSTEMD_MEMPOOL=0` — if set, the internal memory caching logic employed by
  hash tables is turned off, and libc malloc() is used for all allocations.

* `$SYSTEMD_EMOJI=0` — if set, tools such as "systemd-analyze security" will
  not output graphical smiley emojis, but ASCII alternatives instead. Note that
  this only controls use of Unicode emoji glyphs, and has no effect on other
  Unicode glyphs.

systemctl:

* `$SYSTEMCTL_FORCE_BUS=1` — if set, do not connect to PID1's private D-Bus
  listener, and instead always connect through the dbus-daemon D-bus broker.

* `$SYSTEMCTL_INSTALL_CLIENT_SIDE=1` — if set, enable or disable unit files on
  the client side, instead of asking PID 1 to do this.

* `$SYSTEMCTL_SKIP_SYSV=1` — if set, do not call out to SysV compatibility hooks.

systemd-nspawn:

* `$UNIFIED_CGROUP_HIERARCHY=1` — if set, force nspawn into unified cgroup
  hierarchy mode.

* `$SYSTEMD_NSPAWN_API_VFS_WRITABLE=1` — if set, make /sys and /proc/sys and
  friends writable in the container. If set to "network", leave only
  /proc/sys/net writable.

* `$SYSTEMD_NSPAWN_CONTAINER_SERVICE=…` — override the "service" name nspawn
  uses to register with machined. If unset defaults to "nspawn", but with this
  variable may be set to any other value.

* `$SYSTEMD_NSPAWN_USE_CGNS=0` — if set, do not use cgroup namespacing, even if
  it is available.

* `$SYSTEMD_NSPAWN_LOCK=0` — if set, do not lock container images when running.

* `$SYSTEMD_NSPAWN_TMPFS_TMP=0` — if set, do not overmount /tmp in the
  container with a tmpfs, but leave the directory from the image in place.

systemd-logind:

* `$SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK=1` — if set, report that
  hibernation is available even if the swap devices do not provide enough room
  for it.

systemd-udevd:

* `$NET_NAMING_SCHEME=` – if set, takes a network naming scheme (i.e. one of
  "v238", "v239", "v240"…, or the special value "latest") as parameter. If
  specified udev's net_id builtin will follow the specified naming scheme when
  determining stable network interface names. This may be used to revert to
  naming schemes of older udev versions, in order to provide more stable naming
  across updates. This environment variable takes precedence over the kernel
  command line option `net.naming-scheme=`, except if the value is prefixed
  with `:` in which case the kernel command line option takes precedence, if it
  is specified as well.

* `$SYSTEMD_REBOOT_TO_FIRMWARE_SETUP` — if set overrides systemd-logind's
  built-in EFI logic of requesting a reboot into the firmware. Takes a
  boolean. If set to false the functionality is turned off entirely. If set to
  true instead of requesting a reboot into the firmware setup UI through EFI a
  file `/run/systemd/reboot-to-firmware-setup` is created whenever this is
  requested. This file may be checked for by services run during system
  shutdown in order to request the appropriate operation from the firmware in
  an alternative fashion.

* `$SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU` — similar to the above, allows
  overriding of systemd-logind's built-in EFI logic of requesting a reboot into
  the boot loader menu. Takes a boolean. If set to false the functionality is
  turned off entirely. If set to true instead of requesting a reboot into the
  boot loader menu through EFI a file `/run/systemd/reboot-to-boot-loader-menu`
  is created whenever this is requested. The file contains the requested boot
  loader menu timeout in µs, formatted in ASCII decimals, or zero in case no
  time-out is requested. This file may be checked for by services run during
  system shutdown in order to request the appropriate operation from the boot
  loader in an alternative fashion.

* `$SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY` — similar to the above, allows
  overriding of systemd-logind's built-in EFI logic of requesting a reboot into
  a specific boot loader entry. Takes a boolean. If set to false the
  functionality is turned off entirely. If set to true instead of requesting a
  reboot into a specific boot loader entry through EFI a file
  `/run/systemd/reboot-to-boot-loader-entry` is created whenever this is
  requested. The file contains the requested boot loader entry identifier. This
  file may be checked for by services run during system shutdown in order to
  request the appropriate operation from the boot loader in an alternative
  fashion. Note that by default only boot loader entries which follow the [Boot
  Loader Specification](https://systemd.io/BOOT_LOADER_SPECIFICATION) and are
  placed in the ESP or the Extended Boot Loader partition may be selected this
  way. However, if a directory `/run/boot-loader-entries/` exists, the entries
  are loaded from there instead. The directory should contain the usual
  directory hierarchy mandated by the Boot Loader Specification, i.e. the entry
  drop-ins should be placed in
  `/run/boot-loader-entries/loader/entries/*.conf`, and the files referenced by
  the drop-ins (including the kernels and initrds) somewhere else below
  `/run/boot-loader-entries/`. Note that all these files may be (and are
  supposed to be) symlinks. systemd-logind will load these files on-demand,
  these files can hence be updated (ideally atomically) whenever the boot
  loader configuration changes. A foreign boot loader installer script should
  hence synthesize drop-in snippets and symlinks for all boot entries at boot
  or whenever they change if it wants to integrate with systemd-logind's APIs.

installed systemd tests:

* `$SYSTEMD_TEST_DATA` — override the location of test data. This is useful if
  a test executable is moved to an arbitrary location.

nss-systemd:

* `$SYSTEMD_NSS_BYPASS_SYNTHETIC=1` — if set, `nss-systemd` won't synthesize
  user/group records for the `root` and `nobody` users if they are missing from
  `/etc/passwd`.

* `$SYSTEMD_NSS_DYNAMIC_BYPASS=1` — if set, `nss-systemd` won't return
  user/group records for dynamically registered service users (i.e. users
  registered through `DynamicUser=1`).

* `$SYSTEMD_NSS_BYPASS_BUS=1` — if set, `nss-systemd` won't use D-Bus to do
  dynamic user lookups. This is primarily useful to make `nss-systemd` work
  safely from within `dbus-daemon`.

systemd-timedated:

* `$SYSTEMD_TIMEDATED_NTP_SERVICES=…` — colon-separated list of unit names of
  NTP client services. If set, `timedatectl set-ntp on` enables and starts the
  first existing unit listed in the environment variable, and
  `timedatectl set-ntp off` disables and stops all listed units.

systemd-sulogin-shell:

* `$SYSTEMD_SULOGIN_FORCE=1` — This skips asking for the root password if the
  root password is not available (such as when the root account is locked).
  See `sulogin(8)` for more details.

bootctl and other tools that access the EFI System Partition (ESP):

* `$SYSTEMD_RELAX_ESP_CHECKS=1` — if set, the ESP validation checks are
  relaxed. Specifically, validation checks that ensure the specified ESP path
  is a FAT file system are turned off, as are checks that the path is located
  on a GPT partition with the correct type UUID.

* `$SYSTEMD_ESP_PATH=…` — override the path to the EFI System Partition. This
  may be used to override ESP path auto detection, and redirect any accesses to
  the ESP to the specified directory. Not that unlike with bootctl's --path=
  switch only very superficial validation of the specified path is done when
  this environment variable is used.

systemd itself:

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

systemd-remount-fs:

* `$SYSTEMD_REMOUNT_ROOT_RW=1` — if set and no entry for the root directory
  exists in /etc/fstab (this file always takes precedence), then the root
  directory is remounted writable. This is primarily used by
  systemd-gpt-auto-generator to ensure the root partition is mounted writable
  in accordance to the GPT partition flags.

systemd-firstboot and localectl:

* `SYSTEMD_LIST_NON_UTF8_LOCALES=1` – if set non-UTF-8 locales are listed among
  the installed ones. By default non-UTF-8 locales are suppressed from the
  selection, since we are living in the 21st century.
