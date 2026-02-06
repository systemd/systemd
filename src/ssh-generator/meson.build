# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-ssh-generator',
                'sources' : files('ssh-generator.c'),
                'extract' : files('ssh-util.c'),
        },
        libexec_template + {
                'name' : 'systemd-ssh-proxy',
                'sources' : files('ssh-proxy.c'),
        },
        libexec_template + {
                'name' : 'systemd-ssh-issue',
                'sources' : files('ssh-issue.c'),
                'objects' : ['systemd-ssh-generator'],
        },
]

if conf.get('ENABLE_SSH_PROXY_CONFIG') == 1
        custom_target(
                input : '20-systemd-ssh-proxy.conf.in',
                output : '20-systemd-ssh-proxy.conf',
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : true,
                install_dir : sshconfdir.startswith('/usr/') ? sshconfdir : libexecdir / 'ssh_config.d')
endif
