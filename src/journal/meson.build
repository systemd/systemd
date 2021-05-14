# SPDX-License-Identifier: LGPL-2.1-or-later

sources = files('''
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

sources += custom_target(
        'journald-gperf.c',
        input : 'journald-gperf.gperf',
        output : 'journald-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

libjournal_core = static_library(
        'journal-core',
        sources,
        include_directories : includes,
        install : false)

journal_includes = [includes, include_directories('.')]

systemd_journald_sources = files('''
        journald.c
        journald-server.h
'''.split())

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

############################################################

tests += [
        [['src/journal/test-journal-syslog.c'],
         [libjournal_core,
          libshared],
         [threads,
          libxz,
          liblz4,
          libselinux]],

        [['src/journal/test-journal-config.c'],
         [libjournal_core,
          libshared],
         [libxz,
          liblz4,
          libselinux]],
]

fuzzers += [
        [['src/journal/fuzz-journald-audit.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-kmsg.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-native.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-native-fd.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-stream.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-syslog.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],
]
