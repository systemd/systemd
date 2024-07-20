# SPDX-License-Identifier: LGPL-2.1-or-later

in_files = [['locale.conf',   sysconfdir],
            ['vconsole.conf', sysconfdir]]

foreach item : in_files
        file = item[0]
        dir = item[1]

        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : true,
                install_dir : dir)
endforeach
