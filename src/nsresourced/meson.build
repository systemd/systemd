# SPDX-License-Identifier: LGPL-2.1-or-later

subdir('bpf/userns_restrict')

systemd_nsresourcework_sources = files(
        'nsresourcework.c',
        'userns-restrict.c',
        'userns-registry.c',
)

systemd_nsresourced_sources = files(
        'nsresourced-manager.c',
        'nsresourced.c',
        'userns-restrict.c',
        'userns-registry.c',
)

userns_restrict_include = include_directories('.')

if conf.get('HAVE_VMLINUX_H') == 1
        systemd_nsresourcework_sources += userns_restrict_skel_h
        systemd_nsresourced_sources += userns_restrict_skel_h

        executables += [
                test_template + {
                        'sources' : files('test-userns-restrict.c', 'userns-restrict.c') + userns_restrict_skel_h,
                        'conditions' : ['ENABLE_NSRESOURCED', 'HAVE_VMLINUX_H'],
                        'include_directories' : [ includes, userns_restrict_include ],
                },
        ]
endif

executables += [
        libexec_template + {
                'name' : 'systemd-nsresourcework',
                'conditions' : ['ENABLE_NSRESOURCED'],
                'sources' : systemd_nsresourcework_sources,
                'dependencies' : threads,
                'include_directories' : [ includes, userns_restrict_include ],
        },
        libexec_template + {
                'name' : 'systemd-nsresourced',
                'conditions' : ['ENABLE_NSRESOURCED'],
                'sources' : systemd_nsresourced_sources,
                'dependencies' : threads,
                'include_directories' : [ includes, userns_restrict_include ],
        },
]
