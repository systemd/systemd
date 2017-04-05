# -*- mode: meson -*-

systemd_timesyncd_sources = files('''
  timesyncd.c
  timesyncd-manager.c
  timesyncd-manager.h
  timesyncd-conf.c
  timesyncd-conf.h
  timesyncd-server.c
  timesyncd-server.h
'''.split())

timesyncd_gperf_c = custom_target(
    'timesyncd-gperf.c',
    input : 'timesyncd-gperf.gperf',
    output : 'timesyncd-gperf.c',
    command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_timesyncd_sources += [timesyncd_gperf_c]

if conf.get('ENABLE_TIMESYNCD', 0) == 1
  timesyncd_conf = configure_file(
      input : 'timesyncd.conf.in',
      output : 'timesyncd.conf',
      configuration : substs)
  install_data(timesyncd_conf,
               install_dir : pkgsysconfdir)
endif
