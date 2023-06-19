# SPDX-License-Identifier: LGPL-2.1-or-later

busctl_sources = files(
        'busctl-introspect.c',
        'busctl.c',
)

executables += [[
        {
                'name' : 'busctl',
                'public' : true,
        },
        executable_template + {
                'sources' : busctl_sources,
                'dependencies' : [userspace,
                                  versiondep],
        },
]]

tests += [
        {
                'sources' : files(
                        'test-busctl-introspect.c',
                        'busctl-introspect.c',
                )
        },
]
