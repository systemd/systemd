# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_VMSPAWN') != 1
        subdir_done()
endif

libvmspawn_core_sources = files(
        'vmspawn-settings.c',
        'vmspawn-util.c',
        'vmspawn-scope.c',
        'vmspawn-mount.c',
        'vmspawn-register.c',
)

libvmspawn_core = static_library(
        'vmspawn-core',
        libvmspawn_core_sources,
        include_directories : includes,
        dependencies : [userspace],
        build_by_default : false)

vmspawn_libs = [
        libvmspawn_core,
        libshared,
]

vmspawn_test_template = test_template + {
        'link_with' : [vmspawn_libs],
}

executables += [
        executable_template + {
                'name' : 'systemd-vmspawn',
                'public' : true,
                'sources' : files('vmspawn.c'),
                'link_with' : vmspawn_libs,
                'dependencies' : [libblkid]
        },
        vmspawn_test_template + {
                'sources' : files('test-vmspawn-util.c'),
        },
]
