# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_coredump_sources = files(
        'coredump-vacuum.c',
        'coredump.c',
)

coredumpctl_sources = files('coredumpctl.c')

if conf.get('ENABLE_COREDUMP') == 1 and install_sysconfdir_samples
        install_data('coredump.conf', install_dir : pkgsysconfdir)
endif

tests += [
        [files('coredump-vacuum.c', 'test-coredump-vacuum.c'), [], [], [], '', 'manual'],
]
