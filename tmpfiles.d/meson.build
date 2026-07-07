# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_TMPFILES') != 1
        subdir_done()
endif

files = [['README',                  true],
         ['home.conf',               true],
         ['root.conf',               true],
         ['journal-nocow.conf',      true],
         ['portables.conf',          conf.get('ENABLE_PORTABLED') == 1],
         ['systemd-network.conf',    conf.get('ENABLE_NETWORKD') == 1],
         ['systemd-nologin.conf',    conf.get('HAVE_PAM') == 1],
         ['systemd-nspawn.conf',     conf.get('ENABLE_MACHINED') == 1],
         ['systemd-pstore.conf',     conf.get('ENABLE_PSTORE') == 1],
         ['systemd-resolve.conf',    conf.get('ENABLE_RESOLVE') == 1],
         ['20-systemd-varlink.conf', true],
         ['systemd-tmp.conf',        true],
         ['tmp.conf',                true],
         ['x11.conf',                true],
         ['provision.conf',          true],
         ['credstore.conf',          true]]

foreach tuple : files
        if tuple[1]
                install_data(tuple[0], install_dir : tmpfilesdir)
        endif
endforeach

in_files = [
        ['20-systemd-shell-extra.conf',   'LINK_SHELL_EXTRA_DROPIN'      ],
        ['20-systemd-osc-context.conf',   'LINK_OSC_CONTEXT_DROPIN'      ],
        ['20-systemd-ssh-generator.conf', 'ENABLE_SSH_PROXY_CONFIG'      ],
        ['20-systemd-stub.conf',          'ENABLE_EFI'                   ],
        ['20-systemd-userdb.conf',        'ENABLE_SSH_USERDB_CONFIG'     ],
        ['etc.conf'                                                      ],
        ['legacy.conf',                   'ENABLE_COMPAT_SYSV_INTERFACES'],
        ['static-nodes-permissions.conf'                                 ],
        ['systemd.conf'                                                  ],
        ['var.conf'                                                      ],
]

foreach f : in_files
        if f.length() == 1 or conf.get(f[1]) == 1
                custom_target(
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

subdir('user')
