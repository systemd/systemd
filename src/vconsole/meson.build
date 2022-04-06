# SPDX-License-Identifier: LGPL-2.1-or-later

custom_target(
        '90-vconsole.rules',
        input : '90-vconsole.rules.in',
        output : '90-vconsole.rules',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('ENABLE_VCONSOLE') == 1,
        install_dir : udevrulesdir)
