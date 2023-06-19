# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_BLKID') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-gpt-auto-generator',
        },
        generator_template + {
                'sources' : files('gpt-auto-generator.c'),
                'dependencies' : [libblkid,
                                  userspace],
        },
]]
