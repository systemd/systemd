# SPDX-License-Identifier: LGPL-2.1+

systemd_oomd_sources = files('''
        oomd-util.c
        oomd-util.h
'''.split())

if conf.get('ENABLE_OOMD') == 1
        tests += [
                [['src/oom/test-oomd-util.c',
                  'src/oom/oomd-util.c',
                  'src/oom/oomd-util.h'],
                 [],
                 []]
        ]
endif
