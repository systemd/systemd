# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_oomd_sources = files(
        'oomd.c',
        'oomd-conf.c',
        'oomd-manager.c',
        'oomd-manager-bus.c',
        'oomd-util.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-oomd',
                'dbus' : true,
                'conditions' : ['ENABLE_OOMD'],
                'sources' : systemd_oomd_sources,
                'dependencies' : libatomic,
        },
        executable_template + {
                'name' : 'oomctl',
                'public' : true,
                'conditions' : ['ENABLE_OOMD'],
                'sources' : files('oomctl.c'),
        },
        test_template + {
                'sources' : files(
                        'test-oomd-util.c',
                        'oomd-util.c',
                ),
                'dependencies' : libatomic,
        },
]

if conf.get('ENABLE_OOMD') == 1
        install_data('org.freedesktop.oom1.conf',
                     install_dir : dbuspolicydir)

        install_data('org.freedesktop.oom1.service',
                     install_dir : dbussystemservicedir)

        if install_sysconfdir_samples
                install_data('oomd.conf',
                             install_dir : pkgconfigfiledir)
        endif
endif
