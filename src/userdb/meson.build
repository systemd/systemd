# SPDX-License-Identifier: LGPL-2.1-or-later

subdir('bpf/userns_restrict')

systemd_userwork_sources = files(
        'userwork.c',
        'userns-restrict.c',
        'userns-util.c',
)

systemd_userdbd_sources = files(
        'userdbd-manager.c',
        'userdbd.c',
        'userns-restrict.c',
        'userns-util.c',
)

if conf.get('BPF_FRAMEWORK') == 1
        systemd_userwork_sources += userns_restrict_skel_h
        systemd_userdbd_sources += userns_restrict_skel_h
endif

userns_restrict_include = include_directories('.')

test_template += {
        'sources' : files('test-userns-restrict.c', 'userns-restrict.c') + userns_restrict_skel_h,
        'conditions' : ['ENABLE_USERDB', 'BPF_FRAMEWORK'],
        'include_directories' : [ includes, userns_restrict_include ],
}

executables += [
        libexec_template + {
                'name' : 'systemd-userwork',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : systemd_userwork_sources,
                'dependencies' : threads,
                'include_directories' : [ includes, userns_restrict_include ],
        },
        libexec_template + {
                'name' : 'systemd-userdbd',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : systemd_userdbd_sources,
                'dependencies' : threads,
                'include_directories' : [ includes, userns_restrict_include ],
        },
        executable_template + {
                'name' : 'userdbctl',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : files('userdbctl.c'),
                'dependencies' : threads,
                'include_directories' : [ includes, userns_restrict_include ],
        },
]
