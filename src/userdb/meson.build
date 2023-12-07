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

userns_restrict_include = include_directories('.')

if conf.get('BPF_FRAMEWORK') == 1
        systemd_userwork_sources += userns_restrict_skel_h
        systemd_userdbd_sources += userns_restrict_skel_h

        test_template += {
                'sources' : files('test-userns-restrict.c', 'userns-restrict.c') + userns_restrict_skel_h,
                'conditions' : ['ENABLE_USERDB', 'BPF_FRAMEWORK'],
                'include_directories' : [ includes, userns_restrict_include ],
        }
endif

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

custom_target(
        '20-systemd-userdb.conf',
        input : '20-systemd-userdb.conf.in',
        output : '20-systemd-userdb.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('ENABLE_USERDB') == 1 and sshdconfdir != 'no',
        install_dir : libexecdir / 'sshd_config.d')

install_emptydir(sshdconfdir)

meson.add_install_script(sh, '-c',
        ln_s.format(libexecdir / 'sshd_config.d' / '20-systemd-userdb.conf', sshdconfdir / '20-systemd-userdb.conf'))
