# SPDX-License-Identifier: LGPL-2.1-or-later

busctl_sources = files(
        'busctl.c',
)
busctl_export_sources = files(
        'busctl-introspect.c',
)

executables += [
        executable_template + {
                'name' : 'busctl',
                'public' : true,
                'sources' : busctl_sources,
                'export' : busctl_export_sources,
        },
        test_template + {
                'sources' : files('test-busctl-introspect.c'),
                'import' : ['busctl'],
        },
]
