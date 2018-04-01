OpenRC NEWS
===========

This file will contain a list of notable changes for each release. Note
the information in this file is in reverse order.

## OpenRC 0.35

In this version, the cgroups mounting logic has been moved from the
sysfs service to the cgroups service. This was done so cgroups can be
mounted inside an lxc/lxd container without using the other parts of the
sysfs service.

?As a result of this change, if you are upgrading, you need to add
cgroups to your sysinit runlevel by running the following command as
root:

```
# rc-update add cgroups sysinit
```

For more information, see the following issue:

https://github.com/openrc/openrc/issues/187

Consider this your second notification with regard to /etc/mtab being a
file instead of a symbolic link.

In this version, the mtab service will complain loudly if you have
mtab_is_file set to yes and recommend that you change this to no and
restart the mtab service to migrate /etc/mtab to a symbolic link.

If there is a valid technical reason to keep /etc/mtab as a flat file
instead of a symbolic link to /proc/self/mounts, we are interested and
we will keep the support in that case. Please open an issue and let us
know however. Otherwise, consider this your final notice that the mtab
service will be removed in the future.

## OpenRC 0.33

This version removes the "service" binary which was just a copy of
"rc-service" provided for compatibility.

If you still need the "service" binary, as opposed to "rc-service", it is
recommended that you use something like Debian's init-system-helpers.
Otherwise, just use "rc-service" in place of "service".

## OpenRC 0.31

This version adds support for Control Groups version 2, which is
considered stable as of Linux-4.13. Please see /etc/rc.conf for
documentation on how to configure control groups.

## OpenRC-0.28

This version mounts efivars read only due to concerns about changes in
this file system making systems unbootable.  If you need to change something
in this path, you will need to re-mount it read-write, make the change
and re-mount it read-only.

Also, you can override this behavior by adding a line for efivars to
fstab if you want efivars mounted read-write.

For more information on this issue, see the following url:

https://github.com/openrc/openrc/issues/134

## OpenRC-0.25

This version contains an OpenRC-specific implementation of init for
Linux which can be used in place of sysvinit or any other init process.
For information on its usage, see the man pages for openrc-init (8) and
openrc-shutdown (8).

## OpenRC-0.24.1

This version starts cleaning up the dependencies so that rc_parallel
will work correctly.

The first step in this process is to remove the 'before *' from the
depend functions in the clock services. This means some  services not
controlled by OpenRC may now start before instead of after the clock
service. If it is important for these services to start after the clock
service, they need to have 'after clock' added to their depend
functions.

## OpenRC-0.24

Since the deptree2dot tool and the perl requirement are completely
optional, the deptree2dot tool has been moved to the support directory.
As a result, the MKTOOLS=yes/no switch has been removed from the makefiles.

This version adds the agetty service which can be used to spawn
agetty on a specific terminal. This is currently documented in the
agetty-guide.md file at the top level of this distribution.

## OpenRC-0.23

The tmpfiles.d processing code, which was part of previous versions of
OpenRC, has been separated into its own package [1]. If you need to
process systemd style tmpfiles.d files, please install this package.

[1] https://github.com/openrc/opentmpfiles

## OpenRC-0.22

In previous versions of OpenRC, configuration information was processed
so that service-specific configuration stored in /etc/conf.d/* was
overridden by global configuration stored in /etc/rc.conf. This release
reverses that. Global configuration is now overridden by
service-specific configuration.

The swapfiles service, which was basically a copy of the swap service,
has been removed. If you are only using swap partitions, this change
will not affect you. If you are using swap files, please adjust the
dependencies of the swap service as shown in /etc/conf.d/swap.

## OpenRC-0.21

This version adds a daemon supervisor which can start daemons and
restart them if they crash. See supervise-daemon-guide.md in the
distribution for details on its use.

It is now possible to mark certain mount points as critical. If these
mount points are unable to be mounted, localmount or netmount will fail.
This is handled in /etc/conf.d/localmount and /etc/conf.d/netmount. See
these files for the setup.

The deprecation messages in 0.13.x for runscript and rc are now
made visible in preparation for the removal of these binaries in 1.0.

The steps you should take to get rid of these warnings is to run openrc
in initialization steps instead of rc and change the shebang lines in
service scripts to refer to "openrc-run" instead of "runscript".

In 0.21.4, a modules-load service was added. This works like the
equivalent service in systemd. It looks for files named *.conf first in
/usr/lib/modules-load.d, then /run/modules-load.d, then
/etc/modules-load.d. These files contain a list of modules, one per
line, which should be loaded into the kernel. If a file name appears in
/run/modules-load.d, it overrides a file of the same name in
/usr/lib/modules-load.d. A file appearing in /etc/modules-load.d
overrides a file of the same name in both previous directories.

## OpenRC-0.19

This version adds a net-online service. By default, this
service will check all known network interfaces for a configured
interface or a carrier. It will register as started only when all
interfaces are configured and there is at least a carrier on one
interface. The behaviour of this service can be modified in
/etc/conf.d/net-online.

Currently, this only works on Linux, but if anyone wants to port to
*bsd, that would be welcomed.

## OpenRC-0.18.3

Modern Linux systems expect /etc/mtab to be a symbolic link to
/proc/self/mounts. Reasons for this change include support for mount
namespaces, which will not work if /etc/mtab is a file.
By default, the mtab service enforces this on each reboot.

If you find that this breaks your system in some way, please do the
following:

- Set mtab_is_file=yes in /etc/conf.d/mtab.

- Restart mtab. This will recreate the /etc/mtab file.

- Check for an issue on https://github.com/openrc/openrc/issues
  explaining why you need /etc/mtab to be a file. If there isn't one,
  please open one and explain in detail why you need this to be a file.
  If there is one, please add your comments to it. Please give concrete
  examples of why  it is important that /etc/mtab be a file instead of a
  symbolic link. Those comments will be taken into consideration for how
  long to keep supporting mtab as a file or when the support can be
  removed.

## OpenRC-0.18

The behaviour of localmount and netmount in this version is changing. In
the past, these services always started successfully. In this version,
they will be able to fail if file systems they mount fail to mount. If
you have file systems listed in fstab which should not be mounted at
boot time, make sure to add noauto to the mount options. If you have
file systems that you want to attempt to mount at boot time but failure
should be allowed, add nofail to the mount options for these file
systems in fstab.

## OpenRC-0.14

The binfmt service, which registers misc binary formats with the Linux
kernel, has been separated from the procfs service. This service will be
automatically added to the boot runlevel for new Linux installs. When
you upgrade, you will need to use rc-update to add it to your boot
runlevel.

The procfs service no longer automounts the deprecated usbfs and
usbdevfs file systems. Nothing should be using usbdevfs any longer, and
if you still need usbfs it can be added to fstab.

Related to the above change, the procfs service no longer attempts to
modprobe the usbcore module. If your device manager does not load it,
you will need to configure the modules service to do so.

The override order of binfmt.d and tmpfiles.d directories has been
changed to match systemd. Files in /run/binfmt.d and /run/tmpfiles.d
override their /usr/lib counterparts, and files in the /etc counterparts
override both /usr/lib and /run.

## OpenRC-0.13.2

A chroot variable has been added to the service script variables.
This fixes the support for running a service in a chroot.
This is documented in man 8 openrc-run.

The netmount service now mounts nfs file systems.
This change was made to correct a fix for an earlier bug.

## OpenRC-0.13

/sbin/rc was renamed to /sbin/openrc and /sbin/runscript was renamed to
/sbin/openrc-run due to naming conflicts with other software.

Backward compatible symbolic links are currently in place so your
system will keep working if you are using the old names; however, it is
strongly advised that you migrate to the new names because the symbolic
links will be removed in the future.
Warnings have been added to assist with this migration; however, due to the
level of noise they produce, they only appear in verbose mode in this release.

The devfs script now handles the initial mounting and setup of the
/dev directory. If /dev has already been mounted by the kernel or an
initramfs, devfs will remount /dev with the correct mount options
instead of mounting a second /dev over the existing mount point.

It attempts to mount /dev from fstab first if an entry exists there. If
it doesn't it attempts to mount devtmpfs if it is configured in the
kernel. If not, it attempts to mount tmpfs.
If none of these is available, an error message is displayed and static
/dev is assumed.

## OpenRC-0.12

The net.* scripts, originally from Gentoo Linux, have
been removed. If you need these scripts, look for a package called
netifrc, which is maintained by them.
