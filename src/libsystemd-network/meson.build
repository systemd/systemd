# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2017 Zbigniew Jędrzejewski-Szmek
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

sources = files('''
        sd-dhcp-client.c
        sd-dhcp-server.c
        dhcp-network.c
        dhcp-option.c
        dhcp-packet.c
        dhcp-internal.h
        dhcp-server-internal.h
        dhcp-protocol.h
        dhcp-lease-internal.h
        sd-dhcp-lease.c
        sd-ipv4ll.c
        sd-ipv4acd.c
        arp-util.h
        arp-util.c
        network-internal.c
        sd-ndisc.c
        ndisc-internal.h
        ndisc-router.h
        ndisc-router.c
        sd-radv.c
        radv-internal.h
        icmp6-util.h
        icmp6-util.c
        sd-dhcp6-client.c
        dhcp6-internal.h
        dhcp6-protocol.h
        dhcp6-network.c
        dhcp6-option.c
        dhcp6-lease-internal.h
        sd-dhcp6-lease.c
        dhcp-identifier.h
        dhcp-identifier.c
        lldp-internal.h
        lldp-network.h
        lldp-network.c
        lldp-neighbor.h
        lldp-neighbor.c
        sd-lldp.c
'''.split())

network_internal_h = files('network-internal.h')

libsystemd_network = static_library(
        'systemd-network',
        sources,
        network_internal_h,
        include_directories : includes)
