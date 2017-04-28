systemd_journal_upload_sources = files('''
        journal-upload.h
        journal-upload.c
        journal-upload-journal.c
'''.split())

systemd_journal_remote_sources = files('''
        journal-remote-parse.h
        journal-remote-parse.c
        journal-remote-write.h
        journal-remote-write.c
        journal-remote.h
        journal-remote.c
        microhttpd-util.h
        microhttpd-util.c
'''.split())

systemd_journal_gatewayd_sources = files('''
        journal-gatewayd.c
        microhttpd-util.h
        microhttpd-util.c
'''.split())

if conf.get('ENABLE_REMOTE', false) and conf.get('HAVE_LIBCURL', false)
        journal_upload_conf = configure_file(
                input : 'journal-upload.conf.in',
                output : 'journal-upload.conf',
                configuration : substs)
        install_data(journal_upload_conf,
                     install_dir : pkgsysconfdir)
endif

if conf.get('ENABLE_REMOTE', false) and conf.get('HAVE_MICROHTTPD', false)
        journal_remote_conf = configure_file(
                input : 'journal-remote.conf.in',
                output : 'journal-remote.conf',
                configuration : substs)
        install_data(journal_remote_conf,
                     install_dir : pkgsysconfdir)

        install_data('browse.html',
                     install_dir : join_paths(pkgdatadir, 'gatewayd'))

        meson.add_install_script('sh', '-c',
                                 mkdir_p.format('/var/log/journal/remote'))
        meson.add_install_script('sh', '-c',
                                 'chown 0:0 $DESTDIR/var/log/journal/remote &&
                                 chmod 755 $DESTDIR/var/log/journal/remote || :')
endif
