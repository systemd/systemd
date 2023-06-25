# SPDX-License-Identifier: LGPL-2.1-or-later

busctl_sources = files(
        'busctl-introspect.c',
        'busctl.c',
)

executables += [
        executable_template + {
                'name' : 'busctl',
                'public' : true,
                'sources' : busctl_sources,
        },
]

tests += [
        {
                'sources' : files(
                        'test-busctl-introspect.c',
                        'busctl-introspect.c',
                )
        },
]
