# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NSRESOURCED') != 1
        subdir_done()
endif

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

executables += [
        libexec_template + {
                'name' : 'systemd-nsresourced',
                'sources' : systemd_nsresourced_sources,
                'extract' : systemd_nsresourced_extract_sources,
                'dependencies' : threads,
                'bpf_programs': ['userns-restrict'],
        },
        libexec_template + {
                'name' : 'systemd-nsresourcework',
                'sources' : systemd_nsresourcework_sources,
                'dependencies' : threads,
                'objects' : ['systemd-nsresourced'],
                'bpf_programs': ['userns-restrict'],
        },
        test_template + {
                'sources' : test_userns_restrict_sources,
                'conditions' : ['HAVE_VMLINUX_H'],
                'objects' : ['systemd-nsresourced'],
                'bpf_programs': ['userns-restrict'],
        },
]

install_data('io.systemd.namespace-resource.policy',
             install_dir : polkitpolicydir)
