#  SPDX-License-Identifier: LGPL-2.1-or-later
#
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
Description=Container Getty on /dev/pts/%I
Documentation=man:agetty(8) man:systemd-getty-generator(8)
Documentation=man:machinectl(1)
After=systemd-user-sessions.service plymouth-quit-wait.service
m4_ifdef(`HAVE_SYSV_COMPAT',
After=rc-local.service getty-pre.target
)m4_dnl
Before=getty.target
IgnoreOnIsolate=yes
ConditionPathExists=/dev/pts/%I

# IgnoreOnIsolate is an issue: when someone isolates rescue.target,
# tradition expects that we shut down all but the main console.
Conflicts=rescue.service
Before=rescue.service

[Service]
# The '-o' option value tells agetty to replace 'login' arguments with an
# option to preserve environment (-p), followed by '--' for safety, and then
# the entered username.
ExecStart=-/sbin/agetty -o '-p -- \\u' --noclear --keep-baud pts/%I 115200,38400,9600 $TERM
Type=idle
Restart=always
RestartSec=0
UtmpIdentifier=pts/%I
TTYPath=/dev/pts/%I
TTYReset=yes
TTYVHangup=yes
m4_ifdef(`ENABLE_LOGIND',,
KillMode=process
)m4_dnl
IgnoreSIGPIPE=no
SendSIGHUP=yes
