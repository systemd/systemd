# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2017 Zbigniew Jędrzejewski-Szmek

systemd_nspawn_sources = files('''
        nspawn-cgroup.c
        nspawn-cgroup.h
        nspawn-def.h
        nspawn-expose-ports.c
        nspawn-expose-ports.h
        nspawn-mount.c
        nspawn-mount.h
        nspawn-network.c
        nspawn-network.h
        nspawn-patch-uid.c
        nspawn-patch-uid.h
        nspawn-register.c
        nspawn-register.h
        nspawn-seccomp.c
        nspawn-seccomp.h
        nspawn-settings.c
        nspawn-settings.h
        nspawn-setuid.c
        nspawn-setuid.h
        nspawn-stub-pid1.c
        nspawn-stub-pid1.h
        nspawn.c
'''.split())

nspawn_gperf_c = custom_target(
        'nspawn-gperf.c',
        input : 'nspawn-gperf.gperf',
        output : 'nspawn-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_nspawn_sources += [nspawn_gperf_c]

tests += [
        [['src/nspawn/test-patch-uid.c',
          'src/nspawn/nspawn-patch-uid.c',
          'src/nspawn/nspawn-patch-uid.h'],
         [libshared],
         [libacl],
         '', 'manual'],
]
