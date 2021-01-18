# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_coredump_sources = files('''
        coredump.c
        coredump-vacuum.c
        coredump-vacuum.h
'''.split())

if conf.get('HAVE_ELFUTILS') == 1
        systemd_coredump_sources += files(
                'stacktrace.c',
                'stacktrace.h')
endif

coredumpctl_sources = files('coredumpctl.c')

if conf.get('ENABLE_COREDUMP') == 1 and install_sysconfdir_samples
        install_data('coredump.conf',
                     install_dir : pkgsysconfdir)
endif

tests += [
        [['src/coredump/test-coredump-vacuum.c',
          'src/coredump/coredump-vacuum.c',
          'src/coredump/coredump-vacuum.h'],
         [], [], [], '', 'manual'],
]
