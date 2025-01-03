# SPDX-License-Identifier: LGPL-2.1-or-later

libnspawn_core_sources = files(
        'nspawn-bind-user.c',
        'nspawn-cgroup.c',
        'nspawn-expose-ports.c',
        'nspawn-mount.c',
        'nspawn-network.c',
        'nspawn-oci.c',
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

nspawn_libs = [
        libnspawn_core,
        libshared,
]

nspawn_common_template = {
        'link_with' : nspawn_libs,
        'dependencies' : libseccomp,
}
nspawn_test_template = test_template + nspawn_common_template
nspawn_fuzz_template = fuzz_template + nspawn_common_template

executables += [
        executable_template + {
                'name' : 'systemd-nspawn',
                'public' : true,
                'sources' : files('nspawn.c'),
                'link_with' : nspawn_libs,
                'dependencies' : [
                        libblkid,
                        libseccomp,
                ],
        },
        nspawn_test_template + {
                'sources' : files('test-nspawn-tables.c'),
        },
        nspawn_test_template + {
                'sources' : files('test-nspawn-util.c'),
        },
        nspawn_fuzz_template + {
                'sources' : files('fuzz-nspawn-settings.c'),
        },
        nspawn_fuzz_template + {
                'sources' : files('fuzz-nspawn-oci.c'),
        },
]
