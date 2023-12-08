# SPDX-License-Identifier: LGPL-2.1-or-later

enable_tmpfiles = conf.get('ENABLE_TMPFILES') == 1

files = [['README',               ''],
         ['home.conf',            ''],
         ['journal-nocow.conf',   ''],
         ['portables.conf',       'ENABLE_PORTABLED'],
         ['systemd-network.conf', 'ENABLE_NETWORKD'],
         ['systemd-nologin.conf', 'HAVE_PAM'],
         ['systemd-nspawn.conf',  'ENABLE_MACHINED'],
         ['systemd-pstore.conf',  'ENABLE_PSTORE'],
         ['systemd-resolve.conf', 'ENABLE_RESOLVE'],
         ['systemd-tmp.conf',     ''],
         ['tmp.conf',             ''],
         ['x11.conf',             ''],
         ['provision.conf',       ''],
         ['credstore.conf',       ''],
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
            ['20-systemd-userdb.conf',        'ENABLE_USERDB'],
           ]

foreach pair : in_files
        if not enable_tmpfiles
                # do nothing
        elif pair[1] == '' or conf.get(pair[1]) == 1
                custom_target(
                        pair[0],
                        input : pair[0] + '.in',
                        output: pair[0],
                        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                        install : enable_tmpfiles,
                        install_dir : tmpfilesdir)
        else
                message('Not installing tmpfiles.d/@0@ because @1@ is @2@'
                        .format(pair[0], pair[1], conf.get(pair[1], 0)))
        endif
endforeach

if enable_tmpfiles and install_sysconfdir
        install_emptydir(sysconfdir / 'tmpfiles.d')
endif
