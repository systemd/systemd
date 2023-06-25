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
                        libselinux,
                        userspace],
        build_by_default : false)

executables += [
        executable_template + {
                'name' : 'systemd-nspawn',
                'public' : true,
                'sources' : files('nspawn.c'),
                'link_with' : [libnspawn_core,
                               libshared],
                'dependencies' : [libblkid,
                                  libseccomp],
        },
        test_template + {
                'sources' : files('test-nspawn-tables.c'),
                'link_with' : [
                        libnspawn_core,
                        libshared,
                ],
                'dependencies' : libseccomp,
        },
        test_template + {
                'sources' : files('test-nspawn-util.c'),
                'link_with' : [
                        libnspawn_core,
                        libshared,
                ],
                'dependencies' : libseccomp,
        },
        test_template + {
                'sources' : files('test-patch-uid.c'),
                'link_with' : [
                        libnspawn_core,
                        libshared,
                ],
                'dependencies' : libacl,
                'type' : 'manual',
        },
]

fuzzer_nspawn_base = {
        'link_with' : [libshared, libnspawn_core],
        'dependencies' : libseccomp
}

fuzzers += [
        {
                'sources' : files('fuzz-nspawn-settings.c'),
                'base' : fuzzer_nspawn_base,
        },
        {
                'sources' : files('fuzz-nspawn-oci.c'),
                'base' : fuzzer_nspawn_base,
        },
]
