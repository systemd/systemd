#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

[Unit]
Description=Console Shell
After=systemd-user-sessions.service plymouth-quit-wait.service
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
Before=getty.target

[Service]
Environment=HOME=/root
WorkingDirectory=/root
ExecStart=-/sbin/sulogin
ExecStopPost=-/bin/systemctl poweroff
StandardInput=tty-force
KillMode=process

# Bash ignores SIGTERM, so we send SIGHUP instead, to ensure that bash
# terminates cleanly.
KillSignal=SIGHUP

[Install]
WantedBy=getty.target
