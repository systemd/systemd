# SPDX-License-Identifier: LGPL-2.1-or-later

busctl_sources = files(
        'busctl-introspect.c',
        'busctl.c',
)

if get_option('link-busctl-shared')
        busctl_link_with = [libshared]
else
        busctl_link_with = [libsystemd_static,
                            libshared_static]
endif

executables += [
        executable_template + {
                'name' : 'busctl',
                'public' : true,
                'sources' : busctl_sources,
                'link_with' : busctl_link_with,
        },
        test_template + {
                'sources' : files(
                        'test-busctl-introspect.c',
                        'busctl-introspect.c',
                )
        },
]
