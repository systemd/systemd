# SPDX-License-Identifier: LGPL-2.1+

bashcompletiondir = get_option('bashcompletiondir')
if bashcompletiondir == ''
        bash_completion = dependency('bash-completion', required : false)
        if bash_completion.found()
                bashcompletiondir = bash_completion.get_pkgconfig_variable('completionsdir')
        else
                bashcompletiondir = join_paths(datadir, 'bash-completion/completions')
        endif
endif

if bashcompletiondir != 'no'
        bash_systemctl = configure_file(
                input : 'systemctl.in',
                output : 'systemctl',
                configuration : substs)

        items = [['busctl',              ''],
                 ['journalctl',          ''],
                 ['systemd-analyze',     ''],
                 ['systemd-cat',         ''],
                 ['systemd-cgls',        ''],
                 ['systemd-cgtop',       ''],
                 ['systemd-delta',       ''],
                 ['systemd-detect-virt', ''],
                 ['systemd-nspawn',      ''],
                 ['systemd-path',        ''],
                 ['systemd-run',         ''],
                 ['udevadm',             ''],
                 ['kernel-install',      ''],
                 [bash_systemctl,        ''],
                 ['bootctl',             'ENABLE_EFI'],
                 ['coredumpctl',         'ENABLE_COREDUMP'],
                 ['hostnamectl',         'ENABLE_HOSTNAMED'],
                 ['localectl',           'ENABLE_LOCALED'],
                 ['loginctl',            'ENABLE_LOGIND'],
                 ['machinectl',          'ENABLE_MACHINED'],
                 ['networkctl',          'ENABLE_NETWORKD'],
                 ['portablectl',         'ENABLE_PORTABLED'],
                 ['resolvectl',          'ENABLE_RESOLVE'],
                 ['systemd-resolve',     'ENABLE_RESOLVE'],
                 ['timedatectl',         'ENABLE_TIMEDATED'],
                ]

        foreach item : items
                if item[1] == '' or conf.get(item[1]) == 1
                        install_data(item[0],
                                     install_dir : bashcompletiondir)
                endif
        endforeach
endif
