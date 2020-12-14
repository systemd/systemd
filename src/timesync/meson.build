# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_timesyncd_sources = files('''
        aes_siv.c
        aes_siv.h
        timesyncd.c
        timesyncd-bus.c
        timesyncd-bus.h
        timesyncd-conf.c
        timesyncd-conf.h
        timesyncd-nts-client.c
        timesyncd-nts-client.h
        timesyncd-ntp-extension.c
        timesyncd-ntp-extension.h
        timesyncd-ntske-client.c
        timesyncd-ntske-client.h
        timesyncd-ntske-protocol.c
        timesyncd-ntske-protocol.h
        timesyncd-manager.c
        timesyncd-manager.h
        timesyncd-ntp-message.h
        timesyncd-server.c
        timesyncd-server.h
'''.split())

timesyncd_gperf_c = custom_target(
        'timesyncd-gperf.c',
        input : 'timesyncd-gperf.gperf',
        output : 'timesyncd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_timesyncd_sources += [timesyncd_gperf_c]

if conf.get('ENABLE_TIMESYNCD') == 1
        timesyncd_conf = configure_file(
                input : 'timesyncd.conf.in',
                output : 'timesyncd.conf',
                configuration : substs)
        if install_sysconfdir
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
        [['src/timesync/test-timesync.c',
          'src/timesync/timesyncd-manager.c',
          'src/timesync/timesyncd-manager.h',
          'src/timesync/timesyncd-nts-client.c',
          'src/timesync/timesyncd-nts-client.h',
          'src/timesync/timesyncd-ntp-extension.c',
          'src/timesync/timesyncd-ntp-extension.h',
          'src/timesync/timesyncd-ntske-client.c',
          'src/timesync/timesyncd-ntske-client.h',
          'src/timesync/timesyncd-ntske-protocol.c',
          'src/timesync/timesyncd-ntske-protocol.h',
          'src/timesync/timesyncd-conf.c',
          'src/timesync/timesyncd-conf.h',
          'src/timesync/timesyncd-server.c',
          'src/timesync/timesyncd-server.h',
          'src/timesync/aes_siv.c',
          'src/timesync/aes_siv.h',
          timesyncd_gperf_c],
         [libshared],
         [libm],
         'ENABLE_TIMESYNCD'],
]
