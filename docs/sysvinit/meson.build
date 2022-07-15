# SPDX-License-Identifier: LGPL-2.1-or-later

custom_target(
        'README',
        input : 'README.in',
        output : 'README',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('HAVE_SYSV_COMPAT') == 1,
        install_dir : sysvinit_path)
