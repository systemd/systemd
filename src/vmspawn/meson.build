# SPDX-License-Identifier: LGPL-2.1-or-later

libvmspawn_core_sources = files(
        'vmspawn-settings.c',
        'vmspawn-util.c',
        'vmspawn-scope.c',
        'vmspawn-mount.c',
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

executables += [
        executable_template + {
                'name' : 'systemd-vmspawn',
                'public' : true,
                'conditions': ['ENABLE_VMSPAWN'],
                'sources' : files('vmspawn.c'),
                'link_with' : vmspawn_libs,
        }
]
