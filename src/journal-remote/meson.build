# -*- mode: meson -*-

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

if conf.get('ENABLE_REMOTE', 0) == 1 and conf.get('HAVE_LIBCURL', 0) == 1
  journal_upload_conf = configure_file(
      input : 'journal-upload.conf.in',
      output : 'journal-upload.conf',
      configuration : substs)
  install_data(journal_upload_conf,
               install_dir : pkgsysconfdir)
endif

if conf.get('ENABLE_REMOTE', 0) == 1 and conf.get('HAVE_MICROHTTPD', 0) == 1
  journal_remote_conf = configure_file(
      input : 'journal-remote.conf.in',
      output : 'journal-remote.conf',
      configuration : substs)
  install_data(journal_remote_conf,
               install_dir : pkgsysconfdir)
endif

install_data('browse.html',
             install_dir : pkgdatadir + '/gatewayd')
