# SPDX-License-Identifier: LGPL-2.1-or-later

libnspawn_core_sources = files(
        'nspawn-bind-user.c',
        'nspawn-cgroup.c',
        'nspawn-creds.c',
        'nspawn-expose-ports.c',
        'nspawn-mount.c',
        'nspawn-network.c',
        'nspawn-oci.c',
        'nspawn-patch-uid.c',
        'nspawn-register.c',
        'nspawn-seccomp.c',
        'nspawn-settings.c',
        'nspawn-setuid.c',
        'nspawn-stub-pid1.c',
        'nspawn-util.c',
)

nspawn_gperf_c = custom_target(
        'nspawn-gperf.c',
        input : 'nspawn-gperf.gperf',
        output : 'nspawn-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

libnspawn_core_sources += [nspawn_gperf_c]

libnspawn_core = static_library(
        'nspawn-core',
        libnspawn_core_sources,
        include_directories : includes,
        dependencies : [libacl,
                        libseccomp,
                        libselinux],
        build_by_default : false)

systemd_nspawn_sources = files('nspawn.c')

############################################################

tests += [
        [files('test-nspawn-tables.c'),
         [libnspawn_core,
          libshared],
         [libseccomp]],

        [files('test-nspawn-util.c'),
         [libnspawn_core,
          libshared],
         [libseccomp]],

        [files('test-patch-uid.c'),
         [libnspawn_core,
          libshared],
         [libacl],
         [], '', 'manual'],
]

fuzzers += [
        [files('fuzz-nspawn-settings.c'),
         [libshared,
          libnspawn_core],
         [libseccomp]],

        [files('fuzz-nspawn-oci.c'),
         [libshared,
          libnspawn_core],
         [libseccomp]],
]
