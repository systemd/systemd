# SPDX-License-Identifier: LGPL-2.1-or-later

sources = files(
        'netdev/bareudp.c',
        'netdev/batadv.c',
        'netdev/bond.c',
        'netdev/bridge.c',
        'netdev/dummy.c',
        'netdev/fou-tunnel.c',
        'netdev/geneve.c',
        'netdev/ifb.c',
        'netdev/ipoib.c',
        'netdev/ipvlan.c',
        'netdev/l2tp-tunnel.c',
        'netdev/macsec.c',
        'netdev/macvlan.c',
        'netdev/netdev-util.c',
        'netdev/netdev.c',
        'netdev/netdevsim.c',
        'netdev/nlmon.c',
        'netdev/tunnel.c',
        'netdev/tuntap.c',
        'netdev/vcan.c',
        'netdev/veth.c',
        'netdev/vlan.c',
        'netdev/vrf.c',
        'netdev/vxcan.c',
        'netdev/vxlan.c',
        'netdev/wireguard.c',
        'netdev/wlan.c',
        'netdev/xfrm.c',
        'networkd-address-generation.c',
        'networkd-address-label.c',
        'networkd-address-pool.c',
        'networkd-address.c',
        'networkd-bridge-fdb.c',
        'networkd-bridge-mdb.c',
        'networkd-bridge-vlan.c',
        'networkd-can.c',
        'networkd-conf.c',
        'networkd-dhcp-common.c',
        'networkd-dhcp-prefix-delegation.c',
        'networkd-dhcp-server-bus.c',
        'networkd-dhcp-server-static-lease.c',
        'networkd-dhcp-server.c',
        'networkd-dhcp4-bus.c',
        'networkd-dhcp4.c',
        'networkd-dhcp6-bus.c',
        'networkd-dhcp6.c',
        'networkd-ipv4acd.c',
        'networkd-ipv4ll.c',
        'networkd-ipv6-proxy-ndp.c',
        'networkd-ipv6ll.c',
        'networkd-json.c',
        'networkd-link-bus.c',
        'networkd-link.c',
        'networkd-lldp-rx.c',
        'networkd-lldp-tx.c',
        'networkd-manager.c',
        'networkd-manager-bus.c',
        'networkd-manager-varlink.c',
        'networkd-ndisc.c',
        'networkd-neighbor.c',
        'networkd-netlabel.c',
        'networkd-network-bus.c',
        'networkd-network.c',
        'networkd-nexthop.c',
        'networkd-queue.c',
        'networkd-radv.c',
        'networkd-route.c',
        'networkd-route-metric.c',
        'networkd-route-nexthop.c',
        'networkd-route-util.c',
        'networkd-routing-policy-rule.c',
        'networkd-setlink.c',
        'networkd-speed-meter.c',
        'networkd-sriov.c',
        'networkd-state-file.c',
        'networkd-sysctl.c',
        'networkd-util.c',
        'networkd-wifi.c',
        'networkd-wiphy.c',
        'tc/cake.c',
        'tc/codel.c',
        'tc/drr.c',
        'tc/ets.c',
        'tc/fifo.c',
        'tc/fq-codel.c',
        'tc/fq-pie.c',
        'tc/fq.c',
        'tc/gred.c',
        'tc/hhf.c',
        'tc/htb.c',
        'tc/netem.c',
        'tc/pie.c',
        'tc/qdisc.c',
        'tc/qfq.c',
        'tc/sfb.c',
        'tc/sfq.c',
        'tc/tbf.c',
        'tc/tc-util.c',
        'tc/tc.c',
        'tc/tclass.c',
        'tc/teql.c',
)

systemd_networkd_sources = files('networkd.c')

systemd_networkd_wait_online_sources = files(
        'wait-online/link.c',
        'wait-online/manager.c',
        'wait-online/wait-online.c',
)

networkctl_sources = files(
        'networkctl.c',
        'networkctl-config-file.c'
)

network_generator_sources = files(
        'generator/main.c',
        'generator/network-generator.c',
)

networkd_network_gperf_gperf = files('networkd-network-gperf.gperf')
networkd_netdev_gperf_gperf = files('netdev/netdev-gperf.gperf')

sources += custom_target(
        'networkd-gperf.c',
        input : 'networkd-gperf.gperf',
        output : 'networkd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

sources += custom_target(
        'networkd-network-gperf.c',
        input : networkd_network_gperf_gperf,
        output : 'networkd-network-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

sources += custom_target(
        'netdev-gperf.c',
        input : networkd_netdev_gperf_gperf,
        output : 'netdev-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

if get_option('link-networkd-shared')
        networkd_link_with = [libshared]
else
        networkd_link_with = [libsystemd_static,
                              libshared_static,
                              libbasic_gcrypt]
endif

network_includes = [libsystemd_network_includes, include_directories(['.', 'netdev', 'tc'])]

libnetworkd_core = static_library(
        'networkd-core',
        sources,
        include_directories : network_includes,
        dependencies : userspace,
        link_with : networkd_link_with,
        build_by_default : false)

network_test_template = test_template + {
        'link_with' : [
                libnetworkd_core,
                libsystemd_network,
        ],
        'include_directories' : network_includes,
}

network_fuzz_template = fuzz_template + {
        'link_with' : [
                libnetworkd_core,
                libsystemd_network,
        ],
        'dependencies' : threads,
        'include_directories' : network_includes,
}

executables += [
        libexec_template + {
                'name' : 'systemd-networkd',
                'dbus' : true,
                'conditions' : ['ENABLE_NETWORKD'],
                'sources' : systemd_networkd_sources,
                'include_directories' : network_includes,
                'link_with' : [
                        libnetworkd_core,
                        libsystemd_network,
                        networkd_link_with,
                ],
                'dependencies' : threads,
        },
        libexec_template + {
                'name' : 'systemd-networkd-wait-online',
                'public' : true,
                'conditions' : ['ENABLE_NETWORKD'],
                'sources' : systemd_networkd_wait_online_sources,
                'link_with' : networkd_link_with,
        },
        executable_template + {
                'name' : 'networkctl',
                'public' : true,
                'conditions' : ['ENABLE_NETWORKD'],
                'sources' : networkctl_sources,
                'include_directories' : libsystemd_network_includes,
                'link_with' : [
                        libsystemd_network,
                        networkd_link_with,
                ],
        },
        libexec_template + {
                'name' : 'systemd-network-generator',
                'sources' : network_generator_sources,
                'link_with' : networkd_link_with,
        },
        test_template + {
                'sources' : files(
                        'generator/test-network-generator.c',
                        'generator/network-generator.c',
                ),
                'suite' : 'network',
        },
        network_test_template + {
                'sources' : files('test-network-tables.c'),
                'dependencies' : threads,
        },
        network_test_template + {
                'sources' : files('test-network.c'),
                'dependencies' : threads,
        },
        network_test_template + {
                'sources' : files('test-networkd-address.c'),
                'dependencies' : libatomic,
        },
        network_test_template + {
                'sources' : files('test-networkd-conf.c'),
                'dependencies' : libatomic,
        },
        network_test_template + {
                'sources' : files('test-networkd-util.c'),
        },
        network_fuzz_template + {
                'sources' : files('fuzz-netdev-parser.c'),
        },
        network_fuzz_template + {
                'sources' : files('fuzz-network-parser.c'),
        },
]

if conf.get('ENABLE_NETWORKD') == 1
        install_data('org.freedesktop.network1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.network1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.network1.policy',
                     install_dir : polkitpolicydir)
        if install_polkit
                install_data('systemd-networkd.rules',
                             install_dir : polkitrulesdir)
        endif
        if install_polkit_pkla
                install_data('systemd-networkd.pkla',
                             install_dir : polkitpkladir)
        endif

        if install_sysconfdir_samples
                install_data('networkd.conf',
                             install_dir : pkgconfigfiledir)
        endif
endif
