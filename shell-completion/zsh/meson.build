# SPDX-License-Identifier: LGPL-2.1+

zshcompletiondir = get_option('zshcompletiondir')
if zshcompletiondir == ''
        zshcompletiondir = join_paths(datadir, 'zsh/site-functions')
endif

if zshcompletiondir != 'no'
        zsh_systemctl = configure_file(
                input : '_systemctl.in',
                output : '_systemctl',
                configuration : substs)

        items = [['_busctl',                   ''],
                 ['_journalctl',               ''],
                 ['_systemd-analyze',          ''],
                 ['_systemd-delta',            ''],
                 ['_systemd-nspawn',           ''],
                 ['_systemd',                  ''],
                 ['_systemd-run',              ''],
                 ['_udevadm',                  ''],
                 ['_kernel-install',           ''],
                 ['_sd_hosts_or_user_at_host', ''],
                 ['_sd_outputmodes',           ''],
                 ['_sd_unit_files',            ''],
                 ['_sd_machines',              ''],
                 [zsh_systemctl,               ''],
                 ['_bootctl',                  'ENABLE_EFI'],
                 ['_coredumpctl',              'ENABLE_COREDUMP'],
                 ['_hostnamectl',              'ENABLE_HOSTNAMED'],
                 ['_localectl',                'ENABLE_LOCALED'],
                 ['_loginctl',                 'ENABLE_LOGIND'],
                 ['_machinectl',               'ENABLE_MACHINED'],
                 ['_networkctl',               'ENABLE_NETWORKD'],
                 ['_systemd-inhibit',          'ENABLE_LOGIND'],
                 ['_resolvectl',               'ENABLE_RESOLVE'],
                 ['_systemd-tmpfiles',         'ENABLE_TMPFILES'],
                 ['_timedatectl',              'ENABLE_TIMEDATED'],
                ]

        foreach item : items
                if item[1] == '' or conf.get(item[1]) == 1
                        install_data(item[0],
                                     install_dir : zshcompletiondir)
                endif
        endforeach
endif
