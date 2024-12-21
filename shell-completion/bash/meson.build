# SPDX-License-Identifier: LGPL-2.1-or-later

bashcompletiondir = get_option('bashcompletiondir')
if bashcompletiondir == ''
        bash_completion = dependency('bash-completion', required : false)
        if bash_completion.found()
                bashcompletiondir = bash_completion.get_variable(pkgconfig : 'completionsdir')
        else
                bashcompletiondir = datadir / 'bash-completion/completions'
        endif
endif

custom_target(
        'systemctl',
        input : 'systemctl.in',
        output : 'systemctl',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : bashcompletiondir != 'no',
        install_dir : bashcompletiondir)

items = [['busctl',              ''],
         ['journalctl',          ''],
         ['systemd-analyze',     ''],
         ['systemd-cat',         ''],
         ['systemd-cgls',        ''],
         ['systemd-cgtop',       ''],
         ['systemd-creds',       ''],
         ['systemd-delta',       ''],
         ['systemd-detect-virt', ''],
         ['systemd-id128',       ''],
         ['systemd-nspawn',      ''],
         ['systemd-path',        ''],
         ['systemd-run',         ''],
         ['systemd-vpick',       ''],
         ['udevadm',             ''],
         ['bootctl',             ''],
         ['run0',                ''],
         ['coredumpctl',         'ENABLE_COREDUMP'],
         ['homectl',             'ENABLE_HOMED'],
         ['hostnamectl',         'ENABLE_HOSTNAMED'],
         ['importctl',           'ENABLE_IMPORTD'],
         ['kernel-install',      'ENABLE_KERNEL_INSTALL'],
         ['localectl',           'ENABLE_LOCALED'],
         ['loginctl',            'ENABLE_LOGIND'],
         ['machinectl',          'ENABLE_MACHINED'],
         ['networkctl',          'ENABLE_NETWORKD'],
         ['oomctl',              'ENABLE_OOMD'],
         ['portablectl',         'ENABLE_PORTABLED'],
         ['resolvectl',          'ENABLE_RESOLVE'],
         ['systemd-cryptenroll', 'HAVE_LIBCRYPTSETUP'],
         ['systemd-confext',     'ENABLE_SYSEXT'],
         ['systemd-dissect',     'HAVE_BLKID'],
         ['systemd-resolve',     'ENABLE_RESOLVE'],
         ['systemd-sysext',      'ENABLE_SYSEXT'],
         ['systemd-vmspawn',     'ENABLE_VMSPAWN'],
         ['timedatectl',         'ENABLE_TIMEDATED'],
         ['userdbctl',           'ENABLE_USERDB']]

foreach item : items
        if bashcompletiondir != 'no' and (item[1] == '' or conf.get(item[1]) == 1)
                install_data(item[0],
                             install_dir : bashcompletiondir)
        endif
endforeach
