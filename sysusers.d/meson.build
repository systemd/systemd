# SPDX-License-Identifier: LGPL-2.1-or-later

if enable_sysusers
        install_data('README', install_dir : sysusersdir)
endif

in_files = [['basic.conf',          enable_sysusers],
            ['systemd.conf',        enable_sysusers],
            ['systemd-remote.conf', enable_sysusers and
                                    conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_MICROHTTPD') == 1]]

foreach tuple : in_files
        file = tuple[0]
        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [meson_render_jinja2, config_h, '@INPUT@'],
                capture : true,
                install : tuple[1],
                install_dir : sysusersdir)
endforeach
