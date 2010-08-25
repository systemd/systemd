#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

[Unit]
Description=Serial Getty on %I
Requires=dev-%i.device
After=dev-%i.device
m4_ifdef(`TARGET_FEDORA',
After=rc-local.service
)m4_dnl
m4_ifdef(`TARGET_ARCH',
After=rc-local.service
)m4_dnl

# If additional gettys are spawned during boot (possibly by
# systemd-auto-console-getty) then we should make sure that this is
# synchronized before getty.target, even though getty.target didn't
# actually pull it in.
Before=getty.target

[Service]
Environment=TERM=vt100-nav
m4_ifdef(`TARGET_FEDORA',
ExecStartPre=-/sbin/securetty %I
)m4_dnl
ExecStart=-/sbin/agetty -s %I 115200,38400,9600
Restart=restart-always
RestartSec=0
KillMode=process-group

# Some login implementations ignore SIGTERM, so we send SIGHUP
# instead, to ensure that login terminates cleanly.
KillSignal=SIGHUP
