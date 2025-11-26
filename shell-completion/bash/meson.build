# SPDX-License-Identifier: LGPL-2.1-or-later

bashcompletiondir = get_option('bashcompletiondir')
if bashcompletiondir == 'no'
        subdir_done()
elif bashcompletiondir == ''
        bash_completion = dependency('bash-completion', required : false)
        if bash_completion.found()
                bashcompletiondir = bash_completion.get_variable(pkgconfig : 'completionsdir')
        else
                bashcompletiondir = datadir / 'bash-completion/completions'
        endif
endif

custom_target(
        input : 'systemctl.in',
        output : 'systemctl',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : true,
        install_dir : bashcompletiondir)

foreach item : [
        ['bootctl',             ''],
        ['busctl',              ''],
        ['coredumpctl',         'ENABLE_COREDUMP'],
        ['homectl',             'ENABLE_HOMED'],
        ['hostnamectl',         'ENABLE_HOSTNAMED'],
        ['importctl',           'ENABLE_IMPORTD'],
        ['journalctl',          ''],
        ['kernel-install',      'ENABLE_KERNEL_INSTALL'],
        ['localectl',           'ENABLE_LOCALED'],
        ['loginctl',            'ENABLE_LOGIND'],
        ['machinectl',          'ENABLE_MACHINED'],
        ['networkctl',          'ENABLE_NETWORKD'],
        ['oomctl',              'ENABLE_OOMD'],
        ['portablectl',         'ENABLE_PORTABLED'],
        ['resolvectl',          'ENABLE_RESOLVE'],
        ['run0',                ''],
        ['systemd-analyze',     ''],
        ['systemd-cat',         ''],
        ['systemd-cgls',        ''],
        ['systemd-cgtop',       ''],
        ['systemd-confext',     'ENABLE_SYSEXT'],
        ['systemd-creds',       ''],
        ['systemd-cryptenroll', 'HAVE_LIBCRYPTSETUP'],
        ['systemd-delta',       ''],
        ['systemd-detect-virt', ''],
        ['systemd-dissect',     'HAVE_BLKID'],
        ['systemd-id128',       ''],
        ['systemd-nspawn',      'ENABLE_NSPAWN'],
        ['systemd-path',        ''],
        ['systemd-resolve',     'ENABLE_RESOLVE'],
        ['systemd-run',         ''],
        ['systemd-sysext',      'ENABLE_SYSEXT'],
        ['systemd-vmspawn',     'ENABLE_VMSPAWN'],
        ['systemd-vpick',       ''],
        ['timedatectl',         'ENABLE_TIMEDATED'],
        ['udevadm',             ''],
        ['userdbctl',           'ENABLE_USERDB'],
        ['varlinkctl',          ''],
]

        if item[1] == '' or conf.get(item[1]) == 1
                install_data(item[0],
                             install_dir : bashcompletiondir)
        endif
endforeach
