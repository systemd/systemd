# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_oomd_sources = files(
        'oomd-manager-bus.c',
        'oomd-manager.c',
        'oomd-util.c',
        'oomd.c',
)

oomctl_sources = files('oomctl.c')

if conf.get('ENABLE_OOMD') == 1
        install_data('org.freedesktop.oom1.conf',
                     install_dir : dbuspolicydir)

        install_data('org.freedesktop.oom1.service',
                     install_dir : dbussystemservicedir)

        if install_sysconfdir_samples
                install_data('oomd.conf',
                             install_dir : pkgsysconfdir)
        endif
endif

tests += [
        {
                'sources' : files(
                        'test-oomd-util.c',
                        'oomd-util.c',
                ),
                'dependencies' : libatomic,
        },
]
