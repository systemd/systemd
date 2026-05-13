---
title: Tips And Tricks
category: Manuals and Documentation for Users and Administrators
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Tips & Tricks

Also check out the [Frequently Asked Questions](/FAQ)!

## Listing running services

```sh
$ systemctl
UNIT                       LOAD   ACTIVE SUB     JOB DESCRIPTION
accounts-daemon.service    loaded active running     Accounts Service
atd.service                loaded active running     Job spooling tools
avahi-daemon.service       loaded active running     Avahi mDNS/DNS-SD Stack
bluetooth.service          loaded active running     Bluetooth Manager
colord-sane.service        loaded active running     Daemon for monitoring attached scanners and registering them with colord
colord.service             loaded active running     Manage, Install and Generate Color Profiles
crond.service              loaded active running     Command Scheduler
cups.service               loaded active running     CUPS Printing Service
dbus.service               loaded active running     D-Bus System Message Bus
...
```

## Showing runtime status

```sh
$ systemctl status udisks2.service
udisks2.service - Storage Daemon
            Loaded: loaded (/usr/lib/systemd/system/udisks2.service; static)
            Active: active (running) since Wed, 27 Jun 2012 20:49:25 +0200; 1 day and 1h ago
        Main PID: 615 (udisksd)
            CGroup: name=systemd:/system/udisks2.service
                    └ 615 /usr/lib/udisks2/udisksd --no-debug

Jun 27 20:49:25 epsilon udisksd[615]: udisks daemon version 1.94.0 starting
Jun 27 20:49:25 epsilon udisksd[615]: Acquired the name org.freedesktop.UDisks2 on the system message bus
```

## cgroup tree

```sh
$ systemd-cgls
└ system
├ 1 /usr/lib/systemd/systemd --system --deserialize 18
├ ntpd.service
│ └ 8471 /usr/sbin/ntpd -u ntp:ntp -g
├ upower.service
│ └ 798 /usr/libexec/upowerd
├ wpa_supplicant.service
│ └ 751 /usr/sbin/wpa_supplicant -u -f /var/log/wpa_supplicant.log -c /etc/wpa_supplicant/wpa_supplicant.conf -u -f /var/log/wpa_supplicant.log -P /var/run/wpa_supplicant.pid
├ nfs-idmap.service
│ └ 731 /usr/sbin/rpc.idmapd
├ nfs-rquotad.service
│ └ 753 /usr/sbin/rpc.rquotad
├ nfs-mountd.service
│ └ 732 /usr/sbin/rpc.mountd
├ nfs-lock.service
│ └ 704 /sbin/rpc.statd
├ rpcbind.service
│ └ 680 /sbin/rpcbind -w
├ postfix.service
│ ├   859 /usr/libexec/postfix/master
│ ├   877 qmgr -l -t fifo -u
│ └ 32271 pickup -l -t fifo -u
├ colord-sane.service
│ └ 647 /usr/libexec/colord-sane
├ udisks2.service
│ └ 615 /usr/lib/udisks2/udisksd --no-debug
├ colord.service
│ └ 607 /usr/libexec/colord
├ prefdm.service
│ ├ 567 /usr/sbin/gdm-binary -nodaemon
│ ├ 602 /usr/libexec/gdm-simple-slave --display-id /org/gnome/DisplayManager/Display1
│ ├ 612 /usr/bin/Xorg :0 -br -verbose -auth /var/run/gdm/auth-for-gdm-O00GPA/database -seat seat0 -nolisten tcp
│ └ 905 gdm-session-worker [pam/gdm-password]
├ systemd-ask-password-wall.service
│ └ 645 /usr/bin/systemd-tty-ask-password-agent --wall
├ atd.service
│ └ 544 /usr/sbin/atd -f
├ ksmtuned.service
│ ├  548 /bin/bash /usr/sbin/ksmtuned
│ └ 1092 sleep 60
├ dbus.service
│ ├ 586 /bin/dbus-daemon --system --address=systemd: --nofork --systemd-activation
│ ├ 601 /usr/libexec/polkit-1/polkitd --no-debug
│ └ 657 /usr/sbin/modem-manager
├ cups.service
│ └ 508 /usr/sbin/cupsd -f
├ avahi-daemon.service
│ ├ 506 avahi-daemon: running [epsilon.local]
│ └ 516 avahi-daemon: chroot helper
├ system-setup-keyboard.service
│ └ 504 /usr/bin/system-setup-keyboard
├ accounts-daemon.service
│ └ 502 /usr/libexec/accounts-daemon
├ systemd-logind.service
│ └ 498 /usr/lib/systemd/systemd-logind
├ crond.service
│ └ 486 /usr/sbin/crond -n
├ NetworkManager.service
│ ├  484 /usr/sbin/NetworkManager --no-daemon
│ └ 8437 /sbin/dhclient -d -4 -sf /usr/libexec/nm-dhcp-client.action -pf /var/run/dhclient-wlan0.pid -lf /var/lib/dhclient/dhclient-903b6f6aa7a1-46c8-82a9-7f637dfbb3e4-wlan0.lease -cf /var/run/nm-d...
├ libvirtd.service
│ ├ 480 /usr/sbin/libvirtd
│ └ 571 /sbin/dnsmasq --strict-order --bind-interfaces --pid-file=/var/run/libvirt/network/default.pid --conf-file= --except-interface lo --listenaddress 192.168.122.1 --dhcp-range 192.168.122.2,1...
├ bluetooth.service
│ └ 479 /usr/sbin/bluetoothd -n
├ systemd-udev.service
│ └ 287 /usr/lib/systemd/systemd-udevd
└ systemd-journald.service
└ 280 /usr/lib/systemd/systemd-journald
```

### ps with cgroups

```sh
$ alias psc='ps xawf -eo pid,user,cgroup,args'
$ psc
    PID USER     CGROUP                              COMMAND
...
    1 root     name=systemd:/systemd-1             /bin/systemd systemd.log_target=kmsg systemd.log_level=debug selinux=0
    415 root     name=systemd:/systemd-1/sysinit.service /sbin/udevd -d
    928 root     name=systemd:/systemd-1/atd.service /usr/sbin/atd -f
    930 root     name=systemd:/systemd-1/ntpd.service /usr/sbin/ntpd -n
    932 root     name=systemd:/systemd-1/crond.service /usr/sbin/crond -n
    935 root     name=systemd:/systemd-1/auditd.service /sbin/auditd -n
    943 root     name=systemd:/systemd-1/auditd.service  \_ /sbin/audispd
    964 root     name=systemd:/systemd-1/auditd.service      \_ /usr/sbin/sedispatch
    937 root     name=systemd:/systemd-1/acpid.service /usr/sbin/acpid -f
    941 rpc      name=systemd:/systemd-1/rpcbind.service /sbin/rpcbind -f
    944 root     name=systemd:/systemd-1/rsyslog.service /sbin/rsyslogd -n -c 4
    947 root     name=systemd:/systemd-1/systemd-logger.service /lib/systemd/systemd-logger
    950 root     name=systemd:/systemd-1/cups.service /usr/sbin/cupsd -f
    955 dbus     name=systemd:/systemd-1/messagebus.service /bin/dbus-daemon --system --address=systemd: --nofork --systemd-activation
    969 root     name=systemd:/systemd-1/getty@.service/tty6 /sbin/mingetty tty6
    970 root     name=systemd:/systemd-1/getty@.service/tty5 /sbin/mingetty tty5
    971 root     name=systemd:/systemd-1/getty@.service/tty1 /sbin/mingetty tty1
    973 root     name=systemd:/systemd-1/getty@.service/tty4 /sbin/mingetty tty4
    974 root     name=systemd:/user/lennart/2        login -- lennart
    1824 lennart  name=systemd:/user/lennart/2         \_ -bash
    975 root     name=systemd:/systemd-1/getty@.service/tty3 /sbin/mingetty tty3
    988 root     name=systemd:/systemd-1/polkitd.service /usr/libexec/polkit-1/polkitd
    994 rtkit    name=systemd:/systemd-1/rtkit-daemon.service /usr/libexec/rtkit-daemon
...
```

## Changing the Default Boot Target

```sh
$ ln -sf /usr/lib/systemd/system/multi-user.target /etc/systemd/system/default.target
```

This line makes the multi user target (i.e. full system, but no graphical UI) the default target to boot into.
This is kinda equivalent to setting runlevel 3 as the default runlevel on Fedora/sysvinit systems.

```sh
$ ln -sf /usr/lib/systemd/system/graphical.target /etc/systemd/system/default.target
```

This line makes the graphical target (i.e. full system, including graphical UI) the default target to boot into.
Kinda equivalent to runlevel 5 on fedora/sysvinit systems.
This is how things are shipped by default.

## What other units does a unit depend on?

For example, if you want to figure out which services a target like multi-user.target pulls in, use something like this:

```sh
$ systemctl show -p "Wants" multi-user.target
Wants=rc-local.service avahi-daemon.service rpcbind.service NetworkManager.service acpid.service dbus.service atd.service crond.service auditd.service ntpd.service udisks.service bluetooth.service cups.service wpa_supplicant.service getty.target modem-manager.service portreserve.service abrtd.service yum-updatesd.service upowerd.service test-first.service pcscd.service rsyslog.service haldaemon.service remote-fs.target plymouth-quit.service systemd-update-utmp-runlevel.service sendmail.service lvm2-monitor.service cpuspeed.service udev-post.service mdmonitor.service iscsid.service livesys.service livesys-late.service irqbalance.service iscsi.service netfs.service
```

Instead of "Wants" you might also try "WantedBy", "Requires", "RequiredBy", "Conflicts", "ConflictedBy", "Before", "After"
for the respective types of dependencies and their inverse.

## What would get started if I booted into a specific target?

If you want systemd to calculate the "initial" transaction it would execute on boot, try something like this:

```sh
$ systemd --test --system --unit=foobar.target
```

for a boot target foobar.target.
Note that this is mostly a debugging tool that actually does a lot more than just calculate the initial transaction,
so don't build scripts based on this.
