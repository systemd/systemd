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
