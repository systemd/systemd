#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
Description=Container Getty on /dev/pts/%I
Documentation=man:agetty(8) man:machinectl(1)
After=systemd-user-sessions.service plymouth-quit-wait.service
m4_ifdef(`HAVE_SYSV_COMPAT',
After=rc-local.service
)m4_dnl
Before=getty.target
IgnoreOnIsolate=yes
ConditionPathExists=/dev/pts/%I

[Service]
ExecStart=-/sbin/agetty --noclear --keep-baud pts/%I 115200,38400,9600 $TERM
Type=idle
Restart=always
RestartSec=0
UtmpIdentifier=pts/%I
TTYPath=/dev/pts/%I
TTYReset=yes
TTYVHangup=yes
KillMode=process
IgnoreSIGPIPE=no
SendSIGHUP=yes
