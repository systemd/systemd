#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

g systemd-journal   - -
u systemd-bus-proxy - "systemd Bus Proxy"
m4_ifdef(`ENABLE_NETWORKD',
u systemd-network   - "systemd Network Management"
)m4_dnl
m4_ifdef(`ENABLE_RESOLVED',
u systemd-resolve   - "systemd Resolver"
)m4_dnl
m4_ifdef(`ENABLE_TIMESYNCD',
u systemd-timesync  - "systemd Time Synchronization"
)m4_dnl
