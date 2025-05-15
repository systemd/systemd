# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_VMSPAWN') != 1
        subdir_done()
endif

vmspawn_sources = files(
        'vmspawn.c',
        'vmspawn-settings.c',
        'vmspawn-scope.c',
        'vmspawn-mount.c',
        'vmspawn-register.c',
)
vmspawn_extract_sources = files(
        'vmspawn-util.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-vmspawn',
                'public' : true,
                'sources' : vmspawn_sources + vmspawn_extract_sources,
                'extract' : vmspawn_extract_sources,
                'dependencies' : [libblkid]
        },
        test_template + {
                'sources' : files('test-vmspawn-util.c'),
                'objects' : ['systemd-vmspawn'],
        },
]
