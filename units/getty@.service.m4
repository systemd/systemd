#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

[Unit]
Description=Getty on %I
BindTo=dev-%i.device
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
TTYPath=/dev/%I
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
KillMode=process

# Unset locale for the console getty since the console has problems
# displaying some internationalized messages.
Environment=LANG= LC_CTYPE= LC_NUMERIC= LC_TIME= LC_COLLATE= LC_MONETARY= LC_MESSAGES= LC_PAPER= LC_NAME= LC_ADDRESS= LC_TELEPHONE= LC_MEASUREMENT= LC_IDENTIFICATION=

# Some login implementations ignore SIGTERM, so we send SIGHUP
# instead, to ensure that login terminates cleanly.
KillSignal=SIGHUP

[Install]
Alias=getty.target.wants/getty@tty1.service getty.target.wants/getty@tty2.service getty.target.wants/getty@tty3.service getty.target.wants/getty@tty4.service getty.target.wants/getty@tty5.service getty.target.wants/getty@tty6.service
