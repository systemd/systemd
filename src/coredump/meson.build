# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_coredump_sources = files(
        'coredump.c',
        'coredump-vacuum.c',
        'coredump-vacuum.h')

coredumpctl_sources = files('coredumpctl.c')

if conf.get('ENABLE_COREDUMP') == 1 and install_sysconfdir_samples
        install_data('coredump.conf',
                     install_dir : pkgsysconfdir)
endif

tests += [
        [files('test-coredump-vacuum.c',
               'coredump-vacuum.c',
               'coredump-vacuum.h'),
         [], [], [], '', 'manual'],
]
