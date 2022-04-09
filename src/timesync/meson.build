# SPDX-License-Identifier: LGPL-2.1-or-later

sources = files(
        'timesyncd-conf.c',
        'timesyncd-conf.h',
        'timesyncd-manager.c',
        'timesyncd-manager.h',
        'timesyncd-ntp-message.h',
        'timesyncd-server.c',
        'timesyncd-server.h')

systemd_timesyncd_sources = files(
        'timesyncd.c',
        'timesyncd-bus.c',
        'timesyncd-bus.h')

sources += custom_target(
        'timesyncd-gperf.c',
        input : 'timesyncd-gperf.gperf',
        output : 'timesyncd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

if get_option('link-timesyncd-shared')
        timesyncd_link_with = [libshared]
else
        timesyncd_link_with = [libsystemd_static,
                               libshared_static,
                               libbasic_gcrypt]
endif

libtimesyncd_core = static_library(
        'timesyncd-core',
        sources,
        include_directories : includes,
        link_with : timesyncd_link_with,
        build_by_default : false)

custom_target(
        'timesyncd.conf',
        input : 'timesyncd.conf.in',
        output : 'timesyncd.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('ENABLE_TIMESYNCD') == 1 and install_sysconfdir_samples,
        install_dir : pkgsysconfdir)

if conf.get('ENABLE_TIMESYNCD') == 1
        install_data('org.freedesktop.timesync1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.timesync1.service',
                     install_dir : dbussystemservicedir)
        install_data('80-systemd-timesync.list',
                     install_dir : ntpservicelistdir)
        install_data('org.freedesktop.timesync1.policy',
                     install_dir : polkitpolicydir)
endif

############################################################

tests += [
        [files('test-timesync.c'),
         [libtimesyncd_core,
          libshared],
         [libm]],
]
