# SPDX-License-Identifier: LGPL-2.1-or-later

file = configure_file(
        input : 'README.in',
        output : 'README',
        configuration : substs)

if conf.get('HAVE_SYSV_COMPAT') == 1
        install_data(file,
                     install_dir : sysvinit_path)
endif
