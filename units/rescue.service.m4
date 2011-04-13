#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

# See systemd.special(7) for details

[Unit]
Description=Rescue Shell
DefaultDependencies=no
Conflicts=shutdown.target
After=basic.target
Before=shutdown.target

[Service]
Environment=HOME=/root
WorkingDirectory=/root
ExecStartPre=-/bin/plymouth quit
ExecStartPre=-/bin/echo 'Welcome to rescue mode. Use "systemctl default" or ^D to activate default mode.'
m4_ifdef(`TARGET_FEDORA',
`EnvironmentFile=/etc/sysconfig/init
ExecStart=-/bin/bash -c "exec ${SINGLE}"',
m4_ifdef(`TARGET_MANDRIVA',
`EnvironmentFile=/etc/sysconfig/init
ExecStart=-/bin/bash -c "exec ${SINGLE}"',
`ExecStart=-/sbin/sulogin'))
ExecStopPost=-/bin/systemctl --fail --no-block default
StandardInput=tty-force
KillMode=process

# Bash ignores SIGTERM, so we send SIGHUP instead, to ensure that bash
# terminates cleanly.
KillSignal=SIGHUP
