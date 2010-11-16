#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

[Unit]
Description=Getty on %I
BindTo=dev-%i.device
After=dev-%i.device systemd-user-sessions.service
m4_ifdef(`TARGET_FEDORA',
After=rc-local.service
)m4_dnl
m4_ifdef(`TARGET_ARCH',
After=rc-local.service
)m4_dnl

# If additional gettys are spawned during boot then we should make
# sure that this is synchronized before getty.target, even though
# getty.target didn't actually pull it in.
Before=getty.target

[Service]
Environment=TERM=linux
ExecStart=-/sbin/agetty %I 38400
Restart=always
RestartSec=0
UtmpIdentifier=%I
KillMode=process-group

# Some login implementations ignore SIGTERM, so we send SIGHUP
# instead, to ensure that login terminates cleanly.
KillSignal=SIGHUP

[Install]
Alias=getty.target.wants/getty@tty1.service getty.target.wants/getty@tty2.service getty.target.wants/getty@tty3.service getty.target.wants/getty@tty4.service getty.target.wants/getty@tty5.service getty.target.wants/getty@tty6.service
