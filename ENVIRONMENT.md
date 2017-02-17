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

* `$SYSTEMD_IGNORE_CHROOT=1` — if set, don't check whether being invoked in a
  chroot() environment. This is particularly relevant for systemctl, as it will
  not alter its behaviour for chroot() environments if set. (Normally it
  refrains from talking to PID 1 in such a case.)

* `$SD_EVENT_PROFILE_DELAYS=1` — if set, the sd-event event loop implementation
  will print latency information at runtime.

* `$SYSTEMD_PROC_CMDLINE` — if set, may contain a string that is used as kernel
  command line instead of the actual one readable from /proc/cmdline. This is
  useful for debugging, in order to test generators and other code against
  specific kernel command lines.

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
