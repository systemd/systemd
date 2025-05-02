# SPDX-License-Identifier: LGPL-2.1-or-later

sources = files(
        'devlink.c',
        'devlink.h',
        'devlink-kind.c',
        'devlink-kind.h',
        'devlink-key.c',
        'devlink-key.h',
        'devlink-match.c',
        'devlink-match.h',
        'devlink-match-dev.c',
        'devlink-match-dev.h',
        'devlink-match-port.c',
        'devlink-match-port.h',
        'devlink-match-param.c',
        'devlink-reload.c',
        'devlink-reload.h',
        'devlink-nested.c',
        'devlink-nested.h',
        'devlink-dev.c',
        'devlink-dev.h',
        'devlink-port-cache.c',
        'devlink-port-cache.h',
        'devlink-ifname-tracker.c',
        'devlink-ifname-tracker.h',
        'devlink-port.c',
        'devlink-port.h',
        'devlinkd-manager.c',
        'devlinkd-manager.h',
)

systemd_devlinkd_sources = files('devlinkd.c')

devlink_kind_gperf_c = custom_target(
        'devlink-kind-gperf.c',
        input : 'devlink-kind-gperf.gperf',
        output : 'devlink-kind-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

devlink_gperf_c = custom_target(
        'devlink-gperf.c',
        input : 'devlink-gperf.gperf',
        output : 'devlink-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += [devlink_kind_gperf_c, devlink_gperf_c]
sources += [devlink_kind_gperf_c, devlink_gperf_c]

if get_option('link-devlinkd-shared')
        devlinkd_link_with = [libshared]
else
        devlinkd_link_with = [libsystemd_static,
                              libshared_static]
endif

devlink_includes = [includes, include_directories(['.'])]

libdevlinkd_core = static_library(
        'devlinkd-core',
        sources,
        include_directories : devlink_includes,
        dependencies : userspace,
        link_with : devlinkd_link_with,
        build_by_default : false)

executables += [
        libexec_template + {
                'name' : 'systemd-devlinkd',
                'conditions' : ['ENABLE_DEVLINKD'],
                'sources' : systemd_devlinkd_sources,
                'include_directories' : devlink_includes,
                'link_with' : [
                        libdevlinkd_core,
                        devlinkd_link_with,
                ],
        },
]

if conf.get('ENABLE_DEVLINKD') == 1
    install_data('org.freedesktop.devlink1.conf',
                 install_dir : dbuspolicydir)
endif
