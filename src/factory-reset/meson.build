# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-factory-reset',
                'sources' : files('factory-reset-tool.c'),
                'arg_parser' : files('factory-reset-tool.args'),
        },
        generator_template + {
                'name' : 'systemd-factory-reset-generator',
                'sources' : files('factory-reset-generator.c'),
        },
]
