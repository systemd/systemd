#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

m4_ifdef(`TARGET_FEDORA', `m4_define(`GETTY', `/sbin/mingetty')')m4_dnl
m4_ifdef(`TARGET_DEBIAN', `m4_define(`GETTY', `/sbin/getty 38400')')m4_dnl
m4_ifdef(`TARGET_GENTOO', `m4_define(`GETTY', `/sbin/agetty 38400')')m4_dnl
m4_dnl
[Unit]
Description=Getty on %I
Before=getty.target
After=basic.target
Conflicts=shutdown.target

[Service]
Type=simple
ExecStart=GETTY %I
Restart=restart-always
RestartSec=0
