# SPDX-License-Identifier: LGPL-2.1-or-later

sd_journal_sources = files(
        'sd-journal/audit-type.c',
        'sd-journal/catalog.c',
        'sd-journal/fsprg.c',
        'sd-journal/journal-authenticate.c',
        'sd-journal/journal-file.c',
        'sd-journal/journal-send.c',
        'sd-journal/journal-vacuum.c',
        'sd-journal/journal-verify.c',
        'sd-journal/lookup3.c',
        'sd-journal/mmap-cache.c',
        'sd-journal/sd-journal.c',
)

subdir('sd-journal')

generated_sources += audit_type_to_name
sd_journal_sources += audit_type_to_name

############################################################

sd_id128_sources = files(
        'sd-id128/id128-util.c',
        'sd-id128/sd-id128.c',
)

############################################################

sd_daemon_sources = files('sd-daemon/sd-daemon.c')

############################################################

sd_event_sources = files(
        'sd-event/event-util.c',
        'sd-event/sd-event.c',
)

############################################################

sd_bus_sources = files(
        'sd-bus/bus-common-errors.c',
        'sd-bus/bus-container.c',
        'sd-bus/bus-control.c',
        'sd-bus/bus-convenience.c',
        'sd-bus/bus-creds.c',
        'sd-bus/bus-dump.c',
        'sd-bus/bus-dump-json.c',
        'sd-bus/bus-error.c',
        'sd-bus/bus-internal.c',
        'sd-bus/bus-introspect.c',
        'sd-bus/bus-kernel.c',
        'sd-bus/bus-match.c',
        'sd-bus/bus-message.c',
        'sd-bus/bus-objects.c',
        'sd-bus/bus-signature.c',
        'sd-bus/bus-slot.c',
        'sd-bus/bus-socket.c',
        'sd-bus/bus-track.c',
        'sd-bus/bus-type.c',
        'sd-bus/sd-bus.c',
)

############################################################

sd_device_sources = files(
        'sd-device/device-enumerator.c',
        'sd-device/device-filter.c',
        'sd-device/device-monitor.c',
        'sd-device/device-private.c',
        'sd-device/device-util.c',
        'sd-device/sd-device.c',
)

############################################################

sd_login_sources = files('sd-login/sd-login.c')

############################################################

sd_json_sources = files(
        'sd-json/json-stream.c',
        'sd-json/json-util.c',
        'sd-json/sd-json.c',
)

############################################################

sd_varlink_sources = files(
        'sd-varlink/sd-varlink.c',
        'sd-varlink/sd-varlink-idl.c',
        'sd-varlink/varlink-io.systemd.c',
        'sd-varlink/varlink-org.varlink.service.c',
        'sd-varlink/varlink-util.c',
)

############################################################

sd_path_sources = files(
        'sd-path/path-lookup.c',
        'sd-path/sd-path.c',
)

############################################################

sd_netlink_sources = files(
        'sd-netlink/netlink-genl.c',
        'sd-netlink/netlink-message-nfnl.c',
        'sd-netlink/netlink-message-rtnl.c',
        'sd-netlink/netlink-message.c',
        'sd-netlink/netlink-slot.c',
        'sd-netlink/netlink-sock-diag.c',
        'sd-netlink/netlink-socket.c',
        'sd-netlink/netlink-types-genl.c',
        'sd-netlink/netlink-types-nfnl.c',
        'sd-netlink/netlink-types-rtnl.c',
        'sd-netlink/netlink-types-sdnl.c',
        'sd-netlink/netlink-types.c',
        'sd-netlink/netlink-util.c',
        'sd-netlink/sd-netlink.c',
)

############################################################

sd_network_sources = files(
        'sd-network/network-util.c',
        'sd-network/sd-network.c',
)

############################################################

libsystemd_sources = files(
        'sd-hwdb/sd-hwdb.c',
        'sd-resolve/sd-resolve.c',
) + sd_journal_sources + sd_id128_sources + sd_daemon_sources \
  + sd_event_sources + sd_bus_sources + sd_device_sources \
  + sd_login_sources + sd_json_sources + sd_varlink_sources \
  + sd_path_sources + sd_netlink_sources + sd_network_sources

sources += libsystemd_sources

libsystemd_c_args = ['-fvisibility=default']

libsystemd_static = static_library(
        'systemd_static',
        libsystemd_sources,
        include_directories : libsystemd_includes,
        implicit_include_directories : false,
        c_args : libsystemd_c_args,
        link_with : [libc_wrapper_static,
                     libbasic_static],
        dependencies : [threads,
                        libm,
                        librt,
                        userspace],
        build_by_default : false)

libsystemd_dir_path = meson.current_source_dir()

libsystemd_sym = files('libsystemd.sym')
libsystemd_sym_path = libsystemd_dir_path / 'libsystemd.sym'

static_libsystemd = get_option('static-libsystemd')
static_libsystemd_pic = static_libsystemd == 'true' or static_libsystemd == 'pic'

libsystemd_pc = custom_target(
        input : 'libsystemd.pc.in',
        output : 'libsystemd.pc',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : pkgconfiglibdir != 'no',
        install_tag : 'devel',
        install_dir : pkgconfiglibdir)

############################################################

simple_fuzzers += files(
        'sd-bus/fuzz-bus-match.c',
        'sd-bus/fuzz-bus-message.c',
)
