# SPDX-License-Identifier: LGPL-2.1+

id128_sources = files('''
        sd-id128/id128-util.c
        sd-id128/id128-util.h
        sd-id128/sd-id128.c
'''.split())

sd_daemon_sources = files('sd-daemon/sd-daemon.c')

sd_event_sources = files('''
        sd-event/event-source.h
        sd-event/event-util.c
        sd-event/event-util.h
        sd-event/sd-event.c
'''.split())

sd_login_sources = files('sd-login/sd-login.c')

libsystemd_sources = files('''
        sd-bus/bus-common-errors.c
        sd-bus/bus-common-errors.h
        sd-bus/bus-container.c
        sd-bus/bus-container.h
        sd-bus/bus-control.c
        sd-bus/bus-control.h
        sd-bus/bus-convenience.c
        sd-bus/bus-creds.c
        sd-bus/bus-creds.h
        sd-bus/bus-dump.c
        sd-bus/bus-dump.h
        sd-bus/bus-error.c
        sd-bus/bus-error.h
        sd-bus/bus-gvariant.c
        sd-bus/bus-gvariant.h
        sd-bus/bus-internal.c
        sd-bus/bus-internal.h
        sd-bus/bus-introspect.c
        sd-bus/bus-introspect.h
        sd-bus/bus-kernel.c
        sd-bus/bus-kernel.h
        sd-bus/bus-match.c
        sd-bus/bus-match.h
        sd-bus/bus-message.c
        sd-bus/bus-message.h
        sd-bus/bus-objects.c
        sd-bus/bus-objects.h
        sd-bus/bus-protocol.h
        sd-bus/bus-signature.c
        sd-bus/bus-signature.h
        sd-bus/bus-slot.c
        sd-bus/bus-slot.h
        sd-bus/bus-socket.c
        sd-bus/bus-socket.h
        sd-bus/bus-track.c
        sd-bus/bus-track.h
        sd-bus/bus-type.c
        sd-bus/bus-type.h
        sd-bus/sd-bus.c
        sd-device/device-enumerator-private.h
        sd-device/device-enumerator.c
        sd-device/device-internal.h
        sd-device/device-monitor-private.h
        sd-device/device-monitor.c
        sd-device/device-private.c
        sd-device/device-private.h
        sd-device/device-util.h
        sd-device/sd-device.c
        sd-hwdb/hwdb-internal.h
        sd-hwdb/hwdb-util.c
        sd-hwdb/hwdb-util.h
        sd-hwdb/sd-hwdb.c
        sd-netlink/generic-netlink.c
        sd-netlink/netlink-internal.h
        sd-netlink/netlink-message.c
        sd-netlink/netlink-slot.c
        sd-netlink/netlink-slot.h
        sd-netlink/netlink-socket.c
        sd-netlink/netlink-types.c
        sd-netlink/netlink-types.h
        sd-netlink/netlink-util.c
        sd-netlink/netlink-util.h
        sd-netlink/rtnl-message.c
        sd-netlink/sd-netlink.c
        sd-network/network-util.c
        sd-network/network-util.h
        sd-network/sd-network.c
        sd-path/sd-path.c
        sd-resolve/resolve-private.h
        sd-resolve/sd-resolve.c
        sd-utf8/sd-utf8.c
'''.split()) + id128_sources + sd_daemon_sources + sd_event_sources + sd_login_sources

disable_mempool_c = files('disable-mempool.c')

libsystemd_c_args = ['-fvisibility=default']

libsystemd_static = static_library(
        'systemd_static',
        libsystemd_sources,
        install : false,
        include_directories : includes,
        link_with : libbasic,
        dependencies : [threads,
                        librt],
        c_args : libsystemd_c_args)

libsystemd_sym = 'src/libsystemd/libsystemd.sym'

configure_file(
        input : 'libsystemd.pc.in',
        output : 'libsystemd.pc',
        configuration : substs,
        install_dir : pkgconfiglibdir == 'no' ? '' : pkgconfiglibdir)
