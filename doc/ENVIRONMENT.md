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

* `$SYSTEMD_BUS_TIMEOUT=SECS` — specifies the maximum time to wait for method call
  completion. If no time unit is specified, assumes seconds. The usual other units
  are understood, too (us, ms, s, min, h, d, w, month, y). If it is not set or set
  to 0, then the built-in default is used.

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

systemd-logind:

* `$SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK=1` — if set, report that
  hibernation is available even if the swap devices do not provide enough room
  for it.

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
