# SPDX-License-Identifier: LGPL-2.1-or-later

files = [['README',                true],
         ['systemd-coredump.conf', conf.get('ENABLE_COREDUMP') == 1],
         ['systemd-oom.conf',      conf.get('ENABLE_OOMD') == 1],
         ['systemd-remote.conf',   conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_MICROHTTPD') == 1]]

foreach tuple : files
        if enable_sysusers and tuple[1]
                install_data(tuple[0], install_dir : sysusersdir)
        endif
endforeach

in_files = [['basic.conf',            true],
            ['systemd-journal.conf',  true],
            ['systemd-network.conf',  conf.get('ENABLE_NETWORKD') == 1],
            ['systemd-resolve.conf',  conf.get('ENABLE_RESOLVE') == 1],
            ['systemd-timesync.conf', conf.get('ENABLE_TIMESYNCD') == 1]]

foreach tuple : in_files
        file = tuple[0]
        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : enable_sysusers and tuple[1],
                install_dir : sysusersdir)
endforeach
