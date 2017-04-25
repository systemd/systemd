systemd_nspawn_sources = files('''
        nspawn.c
        nspawn-settings.c
        nspawn-settings.h
        nspawn-mount.c
        nspawn-mount.h
        nspawn-network.c
        nspawn-network.h
        nspawn-expose-ports.c
        nspawn-expose-ports.h
        nspawn-cgroup.c
        nspawn-cgroup.h
        nspawn-seccomp.c
        nspawn-seccomp.h
        nspawn-register.c
        nspawn-register.h
        nspawn-setuid.c
        nspawn-setuid.h
        nspawn-stub-pid1.c
        nspawn-stub-pid1.h
        nspawn-patch-uid.c
        nspawn-patch-uid.h
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
