# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_BLKID') != 1
        subdir_done()
endif

executables += [
        generator_template + {
                'name' : 'systemd-gpt-auto-generator',
                'sources' : files('gpt-auto-generator.c'),
                'dependencies' : libblkid,
        },
]
