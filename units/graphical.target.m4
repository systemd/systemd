#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

# See systemd.special(7) for details

[Unit]
Description=Graphical Interface
Requires=multi-user.target
After=multi-user.target
Conflicts=rescue.target
m4_dnl
m4_ifdef(`TARGET_FEDORA',
# On Fedora Runlevel 5 is graphical login
Names=runlevel5.target
)m4_dnl
m4_ifdef(`TARGET_SUSE',
Names=runlevel5.target
)m4_dnl
AllowIsolate=yes

[Install]
Alias=default.target
