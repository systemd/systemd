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
        link_with : [timesyncd_link_with])

if conf.get('ENABLE_TIMESYNCD') == 1
        timesyncd_conf = configure_file(
                input : 'timesyncd.conf.in',
                output : 'timesyncd.conf',
                configuration : substs)
        if install_sysconfdir_samples
                install_data(timesyncd_conf,
                             install_dir : pkgsysconfdir)
        endif
        install_data('org.freedesktop.timesync1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.timesync1.service',
                     install_dir : dbussystemservicedir)
        install_data('80-systemd-timesync.list',
                     install_dir : ntpservicelistdir)
endif

############################################################

tests += [
        [['src/timesync/test-timesync.c'],
         [libtimesyncd_core,
          libshared],
         [libm]],
]
