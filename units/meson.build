# SPDX-License-Identifier: LGPL-2.1+

units = [
        ['basic.target',                        ''],
        ['bluetooth.target',                    ''],
        ['boot-complete.target',                ''],
        ['cryptsetup-pre.target',               'HAVE_LIBCRYPTSETUP'],
        ['cryptsetup.target',                   'HAVE_LIBCRYPTSETUP',
         'sysinit.target.wants/'],
        ['dev-hugepages.mount',                 '',
         'sysinit.target.wants/'],
        ['dev-mqueue.mount',                    '',
         'sysinit.target.wants/'],
        ['emergency.target',                    ''],
        ['exit.target',                         ''],
        ['final.target',                        ''],
        ['getty.target',                        '',
         'multi-user.target.wants/'],
        ['getty-pre.target',                    ''],
        ['graphical.target',                    '',
         'runlevel5.target default.target'],
        ['halt.target',                         ''],
        ['hibernate.target',                    'ENABLE_HIBERNATE'],
        ['hybrid-sleep.target',                 'ENABLE_HIBERNATE'],
        ['suspend-then-hibernate.target',       'ENABLE_HIBERNATE'],
        ['initrd-fs.target',                    ''],
        ['initrd-root-device.target',           ''],
        ['initrd-root-fs.target',               ''],
        ['initrd-switch-root.target',           ''],
        ['initrd.target',                       ''],
        ['kexec.target',                        ''],
        ['ldconfig.service',                    'ENABLE_LDCONFIG',
         'sysinit.target.wants/'],
        ['local-fs-pre.target',                 ''],
        ['local-fs.target',                     ''],
        ['machine.slice',                       'ENABLE_MACHINED'],
        ['machines.target',                     'ENABLE_MACHINED'],
        ['multi-user.target',                   '',
         'runlevel2.target runlevel3.target runlevel4.target'],
        ['network-online.target',               ''],
        ['network-pre.target',                  ''],
        ['network.target',                      ''],
        ['nss-lookup.target',                   ''],
        ['nss-user-lookup.target',              ''],
        ['paths.target',                        ''],
        ['poweroff.target',                     '',
         'runlevel0.target'],
        ['printer.target',                      ''],
        ['proc-sys-fs-binfmt_misc.automount',   'ENABLE_BINFMT',
         'sysinit.target.wants/'],
        ['proc-sys-fs-binfmt_misc.mount',       'ENABLE_BINFMT'],
        ['reboot.target',                       '',
         'runlevel6.target ctrl-alt-del.target'],
        ['remote-cryptsetup.target',            'HAVE_LIBCRYPTSETUP'],
        ['remote-fs-pre.target',                ''],
        ['remote-fs.target',                    ''],
        ['rescue.target',                       '',
         'runlevel1.target'],
        ['rpcbind.target',                      ''],
        ['shutdown.target',                     ''],
        ['sigpwr.target',                       ''],
        ['sleep.target',                        ''],
        ['slices.target',                       ''],
        ['smartcard.target',                    ''],
        ['sockets.target',                      ''],
        ['sound.target',                        ''],
        ['suspend.target',                      ''],
        ['swap.target',                         ''],
        ['sys-fs-fuse-connections.mount',       '',
         'sysinit.target.wants/'],
        ['sys-kernel-config.mount',             '',
         'sysinit.target.wants/'],
        ['sys-kernel-debug.mount',              '',
         'sysinit.target.wants/'],
        ['sysinit.target',                      ''],
        ['syslog.socket',                       ''],
        ['system-update.target',                ''],
        ['system-update-pre.target',            ''],
        ['system-update-cleanup.service',       ''],
        ['systemd-ask-password-console.path',   '',
         'sysinit.target.wants/'],
        ['systemd-ask-password-wall.path',      '',
         'multi-user.target.wants/'],
        ['systemd-coredump.socket',             'ENABLE_COREDUMP',
         'sockets.target.wants/'],
        ['systemd-exit.service',                 ''],
        ['systemd-initctl.socket',              '',
         'sockets.target.wants/'],
        ['systemd-journal-gatewayd.socket',     'ENABLE_REMOTE HAVE_MICROHTTPD'],
        ['systemd-journal-remote.socket',       'ENABLE_REMOTE HAVE_MICROHTTPD'],
        ['systemd-journald-audit.socket',       '',
         'sockets.target.wants/'],
        ['systemd-journald-dev-log.socket',     '',
         'sockets.target.wants/'],
        ['systemd-journald.socket',             '',
         'sockets.target.wants/'],
        ['systemd-networkd.socket',             'ENABLE_NETWORKD'],
        ['systemd-poweroff.service',             ''],
        ['systemd-reboot.service',               ''],
        ['systemd-rfkill.socket',               'ENABLE_RFKILL'],
        ['systemd-tmpfiles-clean.timer',        '',
         'timers.target.wants/'],
        ['systemd-udevd-control.socket',        '',
         'sockets.target.wants/'],
        ['systemd-udevd-kernel.socket',         '',
         'sockets.target.wants/'],
        ['time-set.target',                     ''],
        ['time-sync.target',                    ''],
        ['timers.target',                       ''],
        ['tmp.mount',                           '',
         'local-fs.target.wants/'],
        ['umount.target',                       ''],
        ['user.slice',                          ''],
        ['var-lib-machines.mount',              'ENABLE_MACHINED',
         'remote-fs.target.wants/ machines.target.wants/'],
]

in_units = [
        ['debug-shell.service',                  ''],
        ['emergency.service',                    ''],
        ['initrd-cleanup.service',               ''],
        ['initrd-parse-etc.service',             ''],
        ['initrd-switch-root.service',           ''],
        ['initrd-udevadm-cleanup-db.service',    ''],
        ['kmod-static-nodes.service',            'HAVE_KMOD ENABLE_TMPFILES',
         'sysinit.target.wants/'],
        ['quotaon.service',                      'ENABLE_QUOTACHECK'],
        ['rc-local.service',                     'HAVE_SYSV_COMPAT'],
        ['rescue.service',                       ''],
        ['systemd-ask-password-console.service', ''],
        ['systemd-ask-password-wall.service',    ''],
        ['systemd-backlight@.service',           'ENABLE_BACKLIGHT'],
        ['systemd-binfmt.service',               'ENABLE_BINFMT',
         'sysinit.target.wants/'],
        ['systemd-bless-boot.service',           'ENABLE_EFI HAVE_BLKID'],
        ['systemd-boot-check-no-failures.service', ''],
        ['systemd-boot-system-token.service',    'ENABLE_EFI',
         'sysinit.target.wants/'],
        ['systemd-coredump@.service',            'ENABLE_COREDUMP'],
        ['systemd-pstore.service',               'ENABLE_PSTORE'],
        ['systemd-firstboot.service',            'ENABLE_FIRSTBOOT',
         'sysinit.target.wants/'],
        ['systemd-fsck-root.service',            ''],
        ['systemd-fsck@.service',                ''],
        ['systemd-halt.service',                 ''],
        ['systemd-hibernate-resume@.service',    'ENABLE_HIBERNATE'],
        ['systemd-hibernate.service',            'ENABLE_HIBERNATE'],
        ['systemd-hybrid-sleep.service',         'ENABLE_HIBERNATE'],
        ['systemd-suspend-then-hibernate.service', 'ENABLE_HIBERNATE'],
        ['systemd-hostnamed.service',            'ENABLE_HOSTNAMED',
         'dbus-org.freedesktop.hostname1.service'],
        ['systemd-hwdb-update.service',          'ENABLE_HWDB',
         'sysinit.target.wants/'],
        ['systemd-importd.service',              'ENABLE_IMPORTD',
         'dbus-org.freedesktop.import1.service'],
        ['systemd-initctl.service',               ''],
        ['systemd-journal-catalog-update.service', '',
         'sysinit.target.wants/'],
        ['systemd-journal-flush.service',         '',
         'sysinit.target.wants/'],
        ['systemd-journal-gatewayd.service',     'ENABLE_REMOTE HAVE_MICROHTTPD'],
        ['systemd-journal-remote.service',       'ENABLE_REMOTE HAVE_MICROHTTPD'],
        ['systemd-journal-upload.service',       'ENABLE_REMOTE HAVE_LIBCURL'],
        ['systemd-journald.service',             '',
         'sysinit.target.wants/'],
        ['systemd-kexec.service',                ''],
        ['systemd-localed.service',              'ENABLE_LOCALED',
         'dbus-org.freedesktop.locale1.service'],
        ['systemd-logind.service',               'ENABLE_LOGIND',
         'multi-user.target.wants/ dbus-org.freedesktop.login1.service'],
        ['systemd-machine-id-commit.service',    '',
         'sysinit.target.wants/'],
        ['systemd-machined.service',             'ENABLE_MACHINED',
         'dbus-org.freedesktop.machine1.service'],
        ['systemd-modules-load.service',         'HAVE_KMOD',
         'sysinit.target.wants/'],
        ['systemd-network-generator.service',    'ENABLE_NETWORKD'],
        ['systemd-networkd.service',             'ENABLE_NETWORKD'],
        ['systemd-networkd-wait-online.service', 'ENABLE_NETWORKD'],
        ['systemd-nspawn@.service',              ''],
        ['systemd-portabled.service',            'ENABLE_PORTABLED',
         'dbus-org.freedesktop.portable1.service'],
        ['systemd-quotacheck.service',           'ENABLE_QUOTACHECK'],
        ['systemd-random-seed.service',          'ENABLE_RANDOMSEED',
         'sysinit.target.wants/'],
        ['systemd-remount-fs.service',           ''],
        ['systemd-resolved.service',             'ENABLE_RESOLVE'],
        ['systemd-rfkill.service',               'ENABLE_RFKILL'],
        ['systemd-suspend.service',              ''],
        ['systemd-sysctl.service',               '',
         'sysinit.target.wants/'],
        ['systemd-sysusers.service',             'ENABLE_SYSUSERS',
         'sysinit.target.wants/'],
        ['systemd-timedated.service',            'ENABLE_TIMEDATED',
         'dbus-org.freedesktop.timedate1.service'],
        ['systemd-timesyncd.service',            'ENABLE_TIMESYNCD'],
        ['systemd-time-wait-sync.service',       'ENABLE_TIMESYNCD'],
        ['systemd-tmpfiles-clean.service',       'ENABLE_TMPFILES'],
        ['systemd-tmpfiles-setup-dev.service',   'ENABLE_TMPFILES',
         'sysinit.target.wants/'],
        ['systemd-tmpfiles-setup.service',       'ENABLE_TMPFILES',
         'sysinit.target.wants/'],
        ['systemd-udev-settle.service',          ''],
        ['systemd-udev-trigger.service',         '',
         'sysinit.target.wants/'],
        ['systemd-udevd.service',                '',
         'sysinit.target.wants/'],
        ['systemd-update-done.service',          '',
         'sysinit.target.wants/'],
        ['systemd-update-utmp-runlevel.service', 'ENABLE_UTMP HAVE_SYSV_COMPAT',
         'multi-user.target.wants/ graphical.target.wants/ rescue.target.wants/'],
        ['systemd-update-utmp.service',          'ENABLE_UTMP',
         'sysinit.target.wants/'],
        ['systemd-user-sessions.service',        'HAVE_PAM',
         'multi-user.target.wants/'],
        ['systemd-vconsole-setup.service',       'ENABLE_VCONSOLE'],
        ['systemd-volatile-root.service',        ''],
        ['user-runtime-dir@.service',            ''],
        ['user@.service',                        ''],
]

m4_units = [
        ['console-getty.service',              ''],
        ['container-getty@.service',           ''],
        ['getty@.service',                     '',
         'autovt@.service '],
        ['serial-getty@.service',              ''],
]

foreach tuple : in_units
        file = tuple[0]

        # we do this here because install_data does not accept custom_target output
        conds = tuple[1].split(' ')
        install = ((conds.get(0, '') == '' or conf.get(conds[0]) == 1) and
                   (conds.get(1, '') == '' or conf.get(conds[1]) == 1))

        gen1 = configure_file(
                input : file + '.in',
                output : file + '.tmp',
                configuration : substs)
        gen2 = custom_target(
                file,
                input : gen1,
                output : file,
                command : [sed, '/^## /d', '@INPUT@'],
                capture : true,
                install : install,
                install_dir : systemunitdir)

        if install and tuple.length() > 2
                foreach target : tuple[2].split()
                        meson.add_install_script('meson-add-wants.sh', systemunitdir, target, file)
                endforeach
        endif
endforeach

foreach tuple : m4_units
        file = tuple[0]
        input = tuple.get(3, file + '.m4')

        # we do this here because install_data does not accept custom_target output
        conds = tuple[1].split(' ')
        install = ((conds.get(0, '') == '' or conf.get(conds[0]) == 1) and
                   (conds.get(1, '') == '' or conf.get(conds[1]) == 1))

        custom_target(
                file,
                input : input,
                output: file,
                command : [meson_apply_m4, config_h, '@INPUT@'],
                capture : true,
                install : install,
                install_dir : systemunitdir)

        if tuple.length() > 2 and install
                foreach target : tuple[2].split()
                        meson.add_install_script('meson-add-wants.sh', systemunitdir, target, file)
                endforeach
        endif
endforeach

foreach tuple : units
        file = tuple[0]
        input = tuple.get(3, file)

        conds = tuple[1].split(' ')
        install = ((conds.get(0, '') == '' or conf.get(conds[0]) == 1) and
                   (conds.get(1, '') == '' or conf.get(conds[1]) == 1))

        if install
                install_data(input,
                             install_dir : systemunitdir)

                if tuple.length() > 2
                        foreach target : tuple[2].split()
                                meson.add_install_script(
                                        'meson-add-wants.sh', systemunitdir, target, file)
                        endforeach
                endif
        endif
endforeach

install_data('user-.slice.d/10-defaults.conf',
             install_dir : systemunitdir + '/user-.slice.d')

############################################################

meson.add_install_script(meson_make_symlink,
                         join_paths(pkgsysconfdir, 'user'),
                         join_paths(sysconfdir, 'xdg/systemd/user'))
if conf.get('HAVE_SYSV_COMPAT') == 1
        foreach i : [1, 2, 3, 4, 5]
                meson.add_install_script(
                        'sh', '-c',
                        mkdir_p
                        .format(join_paths(systemunitdir, 'runlevel@0@.target.wants'.format(i))))
        endforeach
endif

subdir('user')
