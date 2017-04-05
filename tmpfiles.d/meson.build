# -*- mode: meson -*-

enable_tmpfiles = conf.get('ENABLE_TMPFILES', 0) == 1

tmpfiles = [['home.conf',            ''],
            ['journal-nocow.conf',   ''],
            ['systemd-nologin.conf', ''],
            ['systemd-nspawn.conf',  ''],
            ['systemd-remote.conf',  'ENABLE_REMOTE'],
            ['tmp.conf',             ''],
            ['var.conf',             ''],
            ['x11.conf',             ''],
            ['legacy.conf',          'HAVE_SYSV_COMPAT'],
           ]

foreach pair : tmpfiles
  if not enable_tmpfiles
    # do nothing
  elif pair[1] == '' or conf.get(pair[1], 0) == 1
    install_data(pair[0], install_dir : tmpfilesdir)
  else
    message('Not installing tmpfiles.d/@0@ because @1@ is @2@'.format(
        pair[0], pair[1], conf.get(pair[1], 0)))
  endif
endforeach

m4_files = ['etc.conf',
            'systemd.conf']

foreach file : m4_files
  custom_target(
    'tmpfiles.d/' + file,
    input : file + '.m4',
    output: file,
    command : [m4, '-P'] + m4_defines + ['@INPUT@'],
    capture : true,
    install : enable_tmpfiles,
    install_dir : tmpfilesdir)
endforeach
