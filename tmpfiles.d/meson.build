# SPDX-License-Identifier: LGPL-2.1-or-later

enable_tmpfiles = conf.get('ENABLE_TMPFILES') == 1

files = [['README',               ''],
         ['home.conf',            ''],
         ['journal-nocow.conf',   ''],
         ['systemd-nologin.conf', 'HAVE_PAM'],
         ['systemd-nspawn.conf',  'ENABLE_MACHINED'],
         ['systemd-resolve.conf', 'ENABLE_RESOLVE'],
         ['systemd-tmp.conf',     ''],
         ['portables.conf',       'ENABLE_PORTABLED'],
         ['systemd-pstore.conf',  'ENABLE_PSTORE'],
         ['tmp.conf',             ''],
         ['x11.conf',             ''],
        ]

foreach pair : files
        if not enable_tmpfiles
                # do nothing
        elif pair[1] == '' or conf.get(pair[1]) == 1
                install_data(pair[0], install_dir : tmpfilesdir)
        else
                message('Not installing tmpfiles.d/@0@ because @1@ is @2@'
                        .format(pair[0], pair[1], conf.get(pair[1], 0)))
        endif
endforeach

in_files = [['etc.conf',                      ''],
            ['legacy.conf',                   'HAVE_SYSV_COMPAT'],
            ['static-nodes-permissions.conf', ''],
            ['systemd.conf',                  ''],
            ['var.conf',                      ''],
           ]

foreach pair : in_files
        if not enable_tmpfiles
                # do nothing
        elif pair[1] == '' or conf.get(pair[1]) == 1
                custom_target(
                        pair[0],
                        input : pair[0] + '.in',
                        output: pair[0],
                        command : [meson_render_jinja2, config_h, '@INPUT@', '@OUTPUT@'],
                        install : enable_tmpfiles,
                        install_dir : tmpfilesdir)
        else
                message('Not installing tmpfiles.d/@0@ because @1@ is @2@'
                        .format(pair[0], pair[1], conf.get(pair[1], 0)))
        endif
endforeach

if enable_tmpfiles and install_sysconfdir
        meson.add_install_script(
                'sh', '-c', mkdir_p.format(sysconfdir / 'tmpfiles.d'))
endif
