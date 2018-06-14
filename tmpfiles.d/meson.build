# SPDX-License-Identifier: LGPL-2.1+

enable_tmpfiles = conf.get('ENABLE_TMPFILES') == 1

tmpfiles = [['home.conf',            ''],
            ['journal-nocow.conf',   ''],
            ['systemd-nologin.conf', ''],
            ['systemd-nspawn.conf',  'ENABLE_MACHINED'],
            ['portables.conf',       'ENABLE_PORTABLED'],
            ['tmp.conf',             ''],
            ['x11.conf',             ''],
            ['legacy.conf',          'HAVE_SYSV_COMPAT'],
           ]

foreach pair : tmpfiles
        if not enable_tmpfiles
                # do nothing
        elif pair[1] == '' or conf.get(pair[1]) == 1
                install_data(pair[0], install_dir : tmpfilesdir)
        else
                message('Not installing tmpfiles.d/@0@ because @1@ is @2@'
                        .format(pair[0], pair[1], conf.get(pair[1], 0)))
        endif
endforeach

m4_files = [['etc.conf',             ''],
            ['systemd.conf',         ''],
            ['var.conf',             ''],
           ]

foreach pair : m4_files
        if not enable_tmpfiles
                # do nothing
        elif pair[1] == '' or conf.get(pair[1]) == 1
                custom_target(
                        'tmpfiles.d_' + pair[0],
                         input : pair[0] + '.m4',
                         output: pair[0],
                         command : [meson_apply_m4, config_h, '@INPUT@'],
                         capture : true,
                         install : true,
                         install_dir : tmpfilesdir)
        else
                message('Not installing tmpfiles.d/@0@.m4 because @1@ is @2@'
                        .format(pair[0], pair[1], conf.get(pair[1], 0)))
        endif
endforeach

if enable_tmpfiles
        meson.add_install_script(
                'sh', '-c',
                mkdir_p.format(join_paths(sysconfdir, 'tmpfiles.d')))
endif
