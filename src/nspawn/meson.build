# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NSPAWN') != 1
        subdir_done()
endif

nspawn_sources = files(
        'nspawn.c',
        'nspawn-bind-user.c',
        'nspawn-cgroup.c',
        'nspawn-register.c',
        'nspawn-seccomp.c',
        'nspawn-setuid.c',
        'nspawn-stub-pid1.c',
)
nspawn_extract_sources = files(
        'nspawn-expose-ports.c',
        'nspawn-mount.c',
        'nspawn-network.c',
        'nspawn-oci.c',
        'nspawn-settings.c',
)

nspawn_gperf_c = custom_target(
        input : 'nspawn-gperf.gperf',
        output : 'nspawn-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += nspawn_gperf_c
nspawn_extract_sources += nspawn_gperf_c

nspawn_common_template = {
        'dependencies' : libseccomp,
        'objects' : ['systemd-nspawn'],
}
nspawn_test_template = test_template + nspawn_common_template
nspawn_fuzz_template = fuzz_template + nspawn_common_template

executables += [
        executable_template + {
                'name' : 'systemd-nspawn',
                'public' : true,
                'sources' : nspawn_sources + nspawn_extract_sources,
                'include_directories' : [
                        executable_template['include_directories'],
                        include_directories('.')
                ],
                'extract' : nspawn_extract_sources,
                'dependencies' : [
                        libblkid,
                        libseccomp,
                        libselinux,
                ],
        },
        nspawn_test_template + {
                'sources' : files('test-nspawn-tables.c'),
        },
        nspawn_fuzz_template + {
                'sources' : files('fuzz-nspawn-settings.c'),
        },
        nspawn_fuzz_template + {
                'sources' : files('fuzz-nspawn-oci.c'),
        },
]
