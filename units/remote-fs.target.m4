#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

# See systemd.special(7) for details

[Unit]
Description=Remote File Systems
m4_dnl
m4_ifdef(`FOR_SYSTEM',
m4_dnl When running in system mode we need the network up
Requires=network.target
After=network.target
)m4_dnl

[Install]
WantedBy=multi-user.target
