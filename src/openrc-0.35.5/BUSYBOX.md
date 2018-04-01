Using Busybox as your Default Shell with OpenRC
===============================================

If you have/bin/sh linked to busybox, you need to be aware of several
incompatibilities between busybox's applets and the standalone
counterparts. Since it is possible to configure busybox to not include
these applets or to prefer the standalone counterparts, OpenRC does not
attempt to support the busybox applets.

For now, it is recommended that you disable the following busybox
configuration settings for best results with OpenRC.

CONFIG_START_STOP_DAEMON -- The start-stop-daemon applet is not compatible with
start-stop-daemon in OpenRC.

CONFIG_MOUNT -- The mount applet does not support the -O [no]_netdev options to
skip over or include network file systems when the -a option is present.

CONFIG_UMOUNT -- The umount applet does not support the -O option along with -a.

CONFIG_SWAPONOFF -- The swapon applet does not support the -e option
or recognize the nofail option in fstab.

CONFIG_SETFONT -- The setfont applet does not support the -u option from kbd.

CONFIG_BB_SYSCTL -- The sysctl applet does not support the --system command
line switch.

There is work to get most of these supported by busybox, so this file
will be updated as things change.
