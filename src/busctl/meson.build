# SPDX-License-Identifier: LGPL-2.1-or-later

busctl_sources = files(
        'busctl.c',
)
busctl_extract_sources = files(
        'busctl-introspect.c',
)

executables += [
        executable_template + {
                'name' : 'busctl',
                'public' : true,
                'sources' : busctl_sources,
                'export' : busctl_extract_sources,
        },
        test_template + {
                'sources' : files('test-busctl-introspect.c'),
                'import' : ['busctl'],
        },
]
