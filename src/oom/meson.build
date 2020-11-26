# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_oomd_sources = files('''
        oomd-manager-bus.c
        oomd-manager-bus.h
        oomd-manager.c
        oomd-manager.h
        oomd-util.c
        oomd-util.h
        oomd.c
'''.split())

oomctl_sources = files('''
        oomctl.c
'''.split())

if conf.get('ENABLE_OOMD') == 1
        tests += [
                [['src/oom/test-oomd-util.c',
                  'src/oom/oomd-util.c',
                  'src/oom/oomd-util.h'],
                 [],
                 []]
        ]

        install_data('org.freedesktop.oom1.conf',
                     install_dir : dbuspolicydir)

        install_data('org.freedesktop.oom1.service',
                     install_dir : dbussystemservicedir)

        if install_sysconfdir
                install_data('oomd.conf',
                             install_dir : pkgsysconfdir)
        endif
endif
