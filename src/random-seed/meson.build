# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-random-seed',
                'conditions' : ['ENABLE_RANDOMSEED'],
                'sources' : files('random-seed-tool.c'),
                'arg_parser' : files('random-seed-tool.args'),
        },
]
