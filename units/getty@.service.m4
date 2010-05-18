#  This file is part of systemd.
#
#  Copyright 2010 Lennart Poettering
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

m4_ifdef(`TARGET_FEDORA', `m4_define(`GETTY', `/sbin/mingetty')')m4_dnl
m4_ifdef(`TARGET_DEBIAN', `m4_define(`GETTY', `/sbin/getty 38400')')m4_dnl
m4_ifdef(`TARGET_GENTOO', `m4_define(`GETTY', `/sbin/agetty 38400')')m4_dnl
m4_dnl
[Unit]
Description=Getty on %I
Before=getty.target
After=basic.target

[Service]
Type=simple
ExecStart=GETTY %I
Restart=restart-always
RestartSec=0
