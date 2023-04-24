# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_userwork_sources = files(
        'userns-restrict.c',
        'userns-util.c',
        'userwork.c',
)

systemd_userdbd_sources = files(
        'userdbd-manager.c',
        'userdbd.c',
        'userns-restrict.c',
        'userns-util.c',
)

subdir('bpf/userns_restrict')

if conf.get('BPF_FRAMEWORK') == 1
        systemd_userwork_sources += [userns_restrict_skel_h]
        systemd_userdbd_sources += [userns_restrict_skel_h]
endif

userdbctl_sources = files('userdbctl.c')

userns_restrict_include = include_directories('.')

tests += [
        {
                'sources' : files('test-userns-restrict.c', 'userns-restrict.c') + [userns_restrict_skel_h],
                'condition' : 'BPF_FRAMEWORK',
                'includes' : [ includes, userns_restrict_include ],
        }
]
