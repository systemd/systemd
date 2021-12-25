# SPDX-License-Identifier: LGPL-2.1-or-later

factory_etc_dir = factorydir / 'etc'

custom_target(
        'locale.conf',
        input : 'locale.conf.in',
        output : 'locale.conf',
        command : [meson_render_jinja2, config_h, '@INPUT@', '@OUTPUT@'],
        install : true,
        install_dir : factory_etc_dir)
