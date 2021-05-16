# SPDX-License-Identifier: LGPL-2.1-or-later

custom_target(
        'README',
        input : 'README.in',
        output : 'README',
        command : [meson_render_jinja2, config_h, '@INPUT@'],
        capture : true,
        install : conf.get('HAVE_SYSV_COMPAT') == 1,
        install_dir : sysvinit_path)
