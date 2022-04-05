# SPDX-License-Identifier: LGPL-2.1-or-later

files = [['README',                ''],
         ['systemd-coredump.conf', 'ENABLE_COREDUMP'],
         ['systemd-oom.conf',      'ENABLE_OOMD']]

foreach pair : files
        if not enable_sysusers
                # do nothing
        elif pair[1] == '' or conf.get(pair[1]) == 1
                install_data(pair[0], install_dir : sysusersdir)
        else
                message('Not installing sysusers.d/@0@ because @1@ is @2@'
                        .format(pair[0], pair[1], conf.get(pair[1], 0)))
        endif
endforeach


if enable_sysusers and conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_MICROHTTPD') == 1
        install_data('systemd-remote.conf', install_dir : sysusersdir)
endif


in_files = [['basic.conf',            enable_sysusers],
            ['systemd-journal.conf',  enable_sysusers],
            ['systemd-network.conf',  enable_sysusers and conf.get('ENABLE_NETWORKD') == 1],
            ['systemd-resolve.conf',  enable_sysusers and conf.get('ENABLE_RESOLVE') == 1],
            ['systemd-timesync.conf', enable_sysusers and conf.get('ENABLE_TIMESYNCD') == 1]]

foreach tuple : in_files
        file = tuple[0]
        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : tuple[1],
                install_dir : sysusersdir)
endforeach
