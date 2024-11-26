# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_TMPFILES') != 1
        subdir_done()
endif

files = [['README'],
         ['home.conf'],
         ['journal-nocow.conf'],
         ['portables.conf',       'ENABLE_PORTABLED'],
         ['systemd-network.conf', 'ENABLE_NETWORKD'],
         ['systemd-nologin.conf', 'HAVE_PAM'],
         ['systemd-nspawn.conf',  'ENABLE_MACHINED'],
         ['systemd-pstore.conf',  'ENABLE_PSTORE'],
         ['systemd-resolve.conf', 'ENABLE_RESOLVE'],
         ['systemd-tmp.conf'],
         ['tmp.conf'],
         ['x11.conf'],
         ['provision.conf'],
         ['credstore.conf'],
        ]

foreach f : files
        if f.length() == 1 or conf.get(f[1]) == 1
                install_data(f[0], install_dir : tmpfilesdir)
        else
                message('Not installing tmpfiles.d/@0@ because @1@ is @2@'
                        .format(f[0], f[1], conf.get(f[1], 0)))
        endif
endforeach

in_files = [
        ['20-systemd-shell-extra.conf',   'LINK_SHELL_EXTRA_DROPIN'],
        ['20-systemd-ssh-generator.conf', 'ENABLE_SSH_PROXY_CONFIG'],
        ['20-systemd-stub.conf',          'ENABLE_EFI'],
        ['20-systemd-userdb.conf',        'ENABLE_SSH_USERDB_CONFIG'],
        ['etc.conf'],
        ['legacy.conf'],
        ['static-nodes-permissions.conf'],
        ['systemd.conf'],
        ['var.conf'],
]

foreach f : in_files
        if f.length() == 1 or conf.get(f[1]) == 1
                custom_target(
                        f[0],
                        input : f[0] + '.in',
                        output: f[0],
                        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                        install : true,
                        install_dir : tmpfilesdir)
        else
                message('Not installing tmpfiles.d/@0@ because @1@ is @2@'
                        .format(f[0], f[1], conf.get(f[1], 0)))
        endif
endforeach

if install_sysconfdir
        install_emptydir(sysconfdir / 'tmpfiles.d')
endif
