# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-socket-proxyd',
                'public' : true,
                'sources' : files('socket-proxyd.c'),
                'arg_parser' : files('socket-proxyd.args'),
                'dependencies' : threads,
        },
]
