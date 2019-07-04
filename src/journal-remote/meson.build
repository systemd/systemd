# SPDX-License-Identifier: LGPL-2.1+

systemd_journal_upload_sources = files('''
        journal-upload.h
        journal-upload.c
        journal-upload-journal.c
'''.split())

libsystemd_journal_remote_sources = files('''
        journal-remote-parse.h
        journal-remote-parse.c
        journal-remote-write.h
        journal-remote-write.c
        journal-remote.h
        journal-remote.c
'''.split())

if conf.get('HAVE_MICROHTTPD') == 1
        libsystemd_journal_remote_sources += files('''
                microhttpd-util.h
                microhttpd-util.c
'''.split())
endif

libsystemd_journal_remote = static_library(
        'systemd-journal-remote',
        libsystemd_journal_remote_sources,
        include_directories : includes,
        dependencies : [threads,
                        libmicrohttpd,
                        libgnutls,
                        libxz,
                        liblz4],
        install : false)

systemd_journal_remote_sources = files('''
        journal-remote-main.c
'''.split())

systemd_journal_gatewayd_sources = files('''
        journal-gatewayd.c
        microhttpd-util.h
        microhttpd-util.c
'''.split())

if conf.get('ENABLE_REMOTE') ==1 and conf.get('HAVE_LIBCURL') == 1
        journal_upload_conf = configure_file(
                input : 'journal-upload.conf.in',
                output : 'journal-upload.conf',
                configuration : substs)
        install_data(journal_upload_conf,
                     install_dir : pkgsysconfdir)
endif

if conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_MICROHTTPD') == 1
        journal_remote_conf = configure_file(
                input : 'journal-remote.conf.in',
                output : 'journal-remote.conf',
                configuration : substs)
        install_data(journal_remote_conf,
                     install_dir : pkgsysconfdir)

        install_data('browse.html',
                     install_dir : join_paths(pkgdatadir, 'gatewayd'))

        if get_option('create-log-dirs')
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format('/var/log/journal/remote'))
                meson.add_install_script('sh', '-c',
                                         '''chown 0:0 $DESTDIR/var/log/journal/remote &&
                                            chmod 755 $DESTDIR/var/log/journal/remote || :''')
        endif
endif
