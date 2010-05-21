#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

# See systemd.special(7) for details

[Unit]
Description=Basic System
Requires=local-fs.target swap.target sockets.target
After=local-fs.target swap.target sockets.target
Conflicts=emergency.service
OnlyByDependency=yes
m4_dnl
m4_ifdef(`TARGET_FEDORA',
m4_dnl Hook in Fedora's /etc/rc.d/rc.sysinit
Requires=sysinit.service
After=sysinit.service
)m4_dnl
