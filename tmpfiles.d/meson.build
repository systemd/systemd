# SPDX-License-Identifier: LGPL-2.1+

enable_tmpfiles = conf.get('ENABLE_TMPFILES') == 1

tmpfiles = [['home.conf',            ''],
            ['journal-nocow.conf',   ''],
            ['systemd-nologin.conf', 'HAVE_PAM'],
            ['systemd-nspawn.conf',  'ENABLE_MACHINED'],
            ['systemd-tmp.conf',     ''],
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

in_files = ['static-nodes-permissions.conf']

foreach file : in_files
        gen = configure_file(
                input : file + '.in',
                output : file,
                configuration : substs)
        if enable_tmpfiles
                install_data(gen,
                             install_dir : tmpfilesdir)
        endif
endforeach

m4_files = ['etc.conf',
            'systemd.conf',
            'var.conf']

foreach file : m4_files
        if enable_tmpfiles
                custom_target(
                        'tmpfiles.d_' + file,
                         input : file + '.m4',
                         output: file,
                         command : [meson_apply_m4, config_h, '@INPUT@'],
                         capture : true,
                         install : true,
                         install_dir : tmpfilesdir)
        endif
endforeach

if enable_tmpfiles
        meson.add_install_script(
                'sh', '-c',
                mkdir_p.format(join_paths(sysconfdir, 'tmpfiles.d')))
endif
