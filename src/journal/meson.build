# SPDX-License-Identifier: LGPL-2.1-or-later

libjournal_core_sources = files('''
        journald-audit.c
        journald-audit.h
        journald-console.c
        journald-console.h
        journald-context.c
        journald-context.h
        journald-kmsg.c
        journald-kmsg.h
        journald-native.c
        journald-native.h
        journald-rate-limit.c
        journald-rate-limit.h
        journald-server.c
        journald-server.h
        journald-stream.c
        journald-stream.h
        journald-syslog.c
        journald-syslog.h
        journald-wall.c
        journald-wall.h
'''.split())

systemd_journald_sources = files('''
        journald.c
        journald-server.h
'''.split())

journald_gperf_c = custom_target(
        'journald-gperf.c',
        input : 'journald-gperf.gperf',
        output : 'journald-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_cat_sources = files('cat.c')

journalctl_sources = files('''
        journalctl.c
        pcre2-dlopen.c
        pcre2-dlopen.h
'''.split())

if install_sysconfdir_samples
        install_data('journald.conf',
                     install_dir : pkgsysconfdir)
endif

if get_option('create-log-dirs')
        meson.add_install_script(
                'sh', '-c',
                mkdir_p.format('/var/log/journal'))
        meson.add_install_script(
                'sh', '-c',
                '''chown 0:0 $DESTDIR/var/log/journal &&
                   chmod 755 $DESTDIR/var/log/journal || :''')
        if get_option('adm-group')
                meson.add_install_script(
                        'sh', '-c',
                        'setfacl -nm g:adm:rx,d:g:adm:rx $DESTDIR/var/log/journal || :')
        endif
        if get_option('wheel-group')
                meson.add_install_script(
                        'sh', '-c',
                        'setfacl -nm g:wheel:rx,d:g:wheel:rx $DESTDIR/var/log/journal || :')
        endif
endif
