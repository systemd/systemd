# SPDX-License-Identifier: LGPL-2.1-or-later

in_files = ['org.freedesktop.hostname1.conf']

foreach file : in_files
        gen = configure_file(
                input : file + '.in',
                output : file,
                configuration : substs)
        if conf.get('ENABLE_HOSTNAMED') == 1
		install_data(gen,
		             install_dir : dbuspolicydir)
        endif
endforeach

if conf.get('ENABLE_HOSTNAMED') == 1
        install_data(gen,
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.hostname1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.hostname1.policy',
                     install_dir : polkitpolicydir)
endif
