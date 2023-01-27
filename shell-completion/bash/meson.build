# SPDX-License-Identifier: LGPL-2.1-or-later

bashcompletiondir = get_option('bashcompletiondir')
if bashcompletiondir == ''
        bash_completion = dependency('bash-completion', required : false)
        if bash_completion.found()
                bashcompletiondir = bash_completion.get_pkgconfig_variable('completionsdir')
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
         ['systemd-delta',       ''],
         ['systemd-detect-virt', ''],
         ['systemd-id128',       ''],
         ['systemd-nspawn',      ''],
         ['systemd-path',        ''],
         ['systemd-run',         ''],
         ['udevadm',             ''],
         ['bootctl',             'HAVE_GNU_EFI'],
         ['coredumpctl',         'ENABLE_COREDUMP'],
         ['homectl',             'ENABLE_HOMED'],
         ['hostnamectl',         'ENABLE_HOSTNAMED'],
         ['kernel-install',      'ENABLE_KERNEL_INSTALL'],
         ['localectl',           'ENABLE_LOCALED'],
         ['loginctl',            'ENABLE_LOGIND'],
         ['machinectl',          'ENABLE_MACHINED'],
         ['networkctl',          'ENABLE_NETWORKD'],
         ['oomctl',              'ENABLE_OOMD'],
         ['portablectl',         'ENABLE_PORTABLED'],
         ['resolvectl',          'ENABLE_RESOLVE'],
         ['systemd-cryptenroll', 'HAVE_LIBCRYPTSETUP'],
         ['systemd-dissect',     'HAVE_BLKID'],
         ['systemd-resolve',     'ENABLE_RESOLVE'],
         ['systemd-sysext',      'ENABLE_SYSEXT'],
         ['timedatectl',         'ENABLE_TIMEDATED']]

foreach item : items
        if bashcompletiondir != 'no' and (item[1] == '' or conf.get(item[1]) == 1)
                install_data(item[0],
                             install_dir : bashcompletiondir)
        endif
endforeach
