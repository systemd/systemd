# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-gpt-auto-generator',
                'conditions' : ['HAVE_BLKID'],
                'sources' : files('gpt-auto-generator.c'),
                'dependencies' : libblkid,
        },
]
