sd_login_c = files('sd-login/sd-login.c')

libsystemd_internal_sources = files('''
        sd-bus/bus-bloom.c
        sd-bus/bus-bloom.h
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
        sd-bus/kdbus.h
        sd-bus/sd-bus.c
        sd-daemon/sd-daemon.c
        sd-device/device-enumerator-private.h
        sd-device/device-enumerator.c
        sd-device/device-internal.h
        sd-device/device-private.c
        sd-device/device-private.h
        sd-device/device-util.h
        sd-device/sd-device.c
        sd-event/sd-event.c
        sd-hwdb/hwdb-internal.h
        sd-hwdb/hwdb-util.h
        sd-hwdb/sd-hwdb.c
        sd-id128/id128-util.c
        sd-id128/id128-util.h
        sd-id128/sd-id128.c
        sd-netlink/local-addresses.c
        sd-netlink/local-addresses.h
        sd-netlink/netlink-internal.h
        sd-netlink/netlink-message.c
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
        sd-resolve/sd-resolve.c
        sd-utf8/sd-utf8.c
'''.split()) + sd_login_c

libsystemd_internal = static_library(
        'systemd',
        libsystemd_internal_sources,
        install : false,
        include_directories : includes,
        link_with : libbasic,
        dependencies : [threads,
                        librt])

libsystemd_sym = 'src/libsystemd/libsystemd.sym'

libsystemd_pc = configure_file(
        input : 'libsystemd.pc.in',
        output : 'libsystemd.pc',
        configuration : substs)
install_data(libsystemd_pc,
             install_dir : pkgconfiglibdir)
