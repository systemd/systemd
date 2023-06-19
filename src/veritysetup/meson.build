# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP') != 1
        subdir_done()
endif

executables += [
        [
                {
                        'name' : 'systemd-veritysetup',
                },
                daemon_template + {
                        'sources' : files('veritysetup.c'),
                        'dependencies' : [libcryptsetup,
                                          userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'systemd-veritysetup-generator',
                },
                generator_template + {
                        'sources' : files('veritysetup-generator.c'),
                },
        ],
]
