# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NSRESOURCED') != 1
        subdir_done()
endif

subdir('bpf/userns-restrict')

systemd_nsresourced_sources = files(
        'nsresourced-manager.c',
        'nsresourced.c',
)
systemd_nsresourced_extract_sources = files(
        'userns-restrict.c',
        'userns-registry.c',
)
systemd_nsresourcework_sources = files(
        'nsresourcework.c'
)
test_userns_restrict_sources = files(
        'test-userns-restrict.c'
)

if conf.get('HAVE_VMLINUX_H') == 1
        systemd_nsresourced_sources += userns_restrict_skel_h
        systemd_nsresourcework_sources += userns_restrict_skel_h
        test_userns_restrict_sources += userns_restrict_skel_h
endif

executables += [
        libexec_template + {
                'name' : 'systemd-nsresourced',
                'sources' : systemd_nsresourced_sources + systemd_nsresourced_extract_sources,
                'include_directories' : [libexec_template['include_directories'], include_directories('.')],
                'extract' : systemd_nsresourced_extract_sources,
                'dependencies' : threads,
        },
        libexec_template + {
                'name' : 'systemd-nsresourcework',
                'sources' : systemd_nsresourcework_sources,
                'dependencies' : threads,
                'objects' : ['systemd-nsresourced'],
        },
        test_template + {
                'sources' : test_userns_restrict_sources,
                'conditions' : ['HAVE_VMLINUX_H'],
                'objects' : ['systemd-nsresourced'],
        },
]

install_data('io.systemd.namespace-resource.policy',
             install_dir : polkitpolicydir)
