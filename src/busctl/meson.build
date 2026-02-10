# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'busctl',
                'public' : true,
                'sources' : files('busctl.c'),
                'arg_parser': files('busctl.args'),
                'extract' : files('busctl-introspect.c'),
        },
        test_template + {
                'sources' : files('test-busctl-introspect.c'),
                'objects' : ['busctl'],
        },
]
