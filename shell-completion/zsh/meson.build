# SPDX-License-Identifier: LGPL-2.1-or-later

zshcompletiondir = get_option('zshcompletiondir')
if zshcompletiondir == ''
        zshcompletiondir = datadir / 'zsh/site-functions'
endif

custom_target(
        '_systemctl',
        input : '_systemctl.in',
        output : '_systemctl',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : zshcompletiondir != 'no',
        install_dir : zshcompletiondir)

items = [['_busctl',                   ''],
         ['_journalctl',               ''],
         ['_systemd-analyze',          ''],
         ['_systemd-delta',            ''],
         ['_systemd-nspawn',           ''],
         ['_systemd',                  ''],
         ['_systemd-path',             ''],
         ['_systemd-run',              ''],
         ['_run0',                     ''],
         ['_udevadm',                  ''],
         ['_varlinkctl',               ''],
         ['_kernel-install',           'ENABLE_KERNEL_INSTALL'],
         ['_sd_hosts_or_user_at_host', ''],
         ['_sd_outputmodes',           ''],
         ['_sd_unit_files',            ''],
         ['_sd_machines',              ''],
         ['_bootctl',                  ''],
         ['_coredumpctl',              'ENABLE_COREDUMP'],
         ['_hostnamectl',              'ENABLE_HOSTNAMED'],
         ['_localectl',                'ENABLE_LOCALED'],
         ['_loginctl',                 'ENABLE_LOGIND'],
         ['_machinectl',               'ENABLE_MACHINED'],
         ['_networkctl',               'ENABLE_NETWORKD'],
         ['_oomctl',                   'ENABLE_OOMD'],
         ['_systemd-inhibit',          'ENABLE_LOGIND'],
         ['_resolvectl',               'ENABLE_RESOLVE'],
         ['_systemd-tmpfiles',         'ENABLE_TMPFILES'],
         ['_timedatectl',              'ENABLE_TIMEDATED']]

foreach item : items
        if zshcompletiondir != 'no' and (item[1] == '' or conf.get(item[1]) == 1)
                install_data(item[0],
                             install_dir : zshcompletiondir)
        endif
endforeach
