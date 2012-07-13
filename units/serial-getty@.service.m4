#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
Description=Serial Getty on %I
Documentation=man:agetty(8) man:systemd-getty-generator(8)
BindsTo=dev-%i.device
After=dev-%i.device systemd-user-sessions.service plymouth-quit-wait.service
m4_ifdef(`TARGET_FEDORA',
After=rc-local.service
)m4_dnl
m4_ifdef(`TARGET_ARCH',
After=rc-local.service
)m4_dnl
m4_ifdef(`TARGET_FRUGALWARE',
After=local.service
)m4_dnl
m4_ifdef(`TARGET_ALTLINUX',
After=rc-local.service
)m4_dnl
m4_ifdef(`TARGET_MANDRIVA',
After=rc-local.service
)m4_dnl
m4_ifdef(`TARGET_MAGEIA',
After=rc-local.service
)m4_dnl

# If additional gettys are spawned during boot then we should make
# sure that this is synchronized before getty.target, even though
# getty.target didn't actually pull it in.
Before=getty.target
IgnoreOnIsolate=yes

[Service]
Environment=TERM=vt102
ExecStart=-/sbin/agetty -s %I 115200,38400,9600
Type=idle
Restart=always
RestartSec=0
UtmpIdentifier=%I
TTYPath=/dev/%I
TTYReset=yes
TTYVHangup=yes
KillMode=process
IgnoreSIGPIPE=no

# Some login implementations ignore SIGTERM, so we send SIGHUP
# instead, to ensure that login terminates cleanly.
KillSignal=SIGHUP
