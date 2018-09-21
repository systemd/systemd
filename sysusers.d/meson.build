# SPDX-License-Identifier: LGPL-2.1+

in_files = ['basic.conf']

enable_sysusers = conf.get('ENABLE_SYSUSERS') == 1

foreach file : in_files
        gen = configure_file(
                input : file + '.in',
                output : file,
                configuration : substs)
        if enable_sysusers
                install_data(gen,
                             install_dir : sysusersdir)
        endif
endforeach

m4_files = ['systemd.conf']

if conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_MICROHTTPD') == 1
        m4_files += ['systemd-remote.conf']
endif

foreach file : m4_files
        custom_target(
                'sysusers.d_' + file,
                input : file + '.m4',
                output: file,
                command : [meson_apply_m4, config_h, '@INPUT@'],
                capture : true,
                install : enable_sysusers,
                install_dir : sysusersdir)
endforeach
