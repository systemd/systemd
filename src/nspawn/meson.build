# SPDX-License-Identifier: LGPL-2.1-or-later

libnspawn_core_sources = files(
        'nspawn-bind-user.c',
        'nspawn-bind-user.h',
        'nspawn-cgroup.c',
        'nspawn-cgroup.h',
        'nspawn-creds.c',
        'nspawn-creds.h',
        'nspawn-def.h',
        'nspawn-expose-ports.c',
        'nspawn-expose-ports.h',
        'nspawn-mount.c',
        'nspawn-mount.h',
        'nspawn-network.c',
        'nspawn-network.h',
        'nspawn-oci.c',
        'nspawn-oci.h',
        'nspawn-patch-uid.c',
        'nspawn-patch-uid.h',
        'nspawn-register.c',
        'nspawn-register.h',
        'nspawn-seccomp.c',
        'nspawn-seccomp.h',
        'nspawn-settings.c',
        'nspawn-settings.h',
        'nspawn-setuid.c',
        'nspawn-setuid.h',
        'nspawn-stub-pid1.c',
        'nspawn-stub-pid1.h',
        'nspawn-util.c',
        'nspawn-util.h',
        'nspawn.h',
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
