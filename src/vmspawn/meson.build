# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_VMSPAWN') != 1
        subdir_done()
endif

vmspawn_sources = files(
        'vmspawn.c',
        'vmspawn-bind-volume.c',
        'vmspawn-qmp.c',
        'vmspawn-varlink.c',
        'vmspawn-settings.c',
        'vmspawn-scope.c',
        'vmspawn-mount.c',
)
vmspawn_export_sources = files(
        'vmspawn-util.c',
        'vmspawn-qemu-config.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-vmspawn',
                'public' : true,
                'sources' : vmspawn_sources,
                'export' : vmspawn_export_sources,
        },
        test_template + {
                'sources' : files('test-vmspawn-util.c'),
                'import' : ['systemd-vmspawn'],
        },
        test_template + {
                'sources' : files('test-vmspawn-qemu-config.c'),
                'import' : ['systemd-vmspawn'],
        },
]
