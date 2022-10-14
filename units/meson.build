# SPDX-License-Identifier: LGPL-2.1-or-later

with_runlevels = conf.get('HAVE_SYSV_COMPAT') == 1

units = [
        ['basic.target',                        ''],
        ['blockdev@.target',                    ''],
        ['bluetooth.target',                    ''],
        ['boot-complete.target',                ''],
        ['cryptsetup-pre.target',               'HAVE_LIBCRYPTSETUP'],
        ['cryptsetup.target',                   'HAVE_LIBCRYPTSETUP',
         'sysinit.target.wants/'],
        ['veritysetup-pre.target',              'HAVE_LIBCRYPTSETUP'],
        ['veritysetup.target',                  'HAVE_LIBCRYPTSETUP',
         'sysinit.target.wants/'],
        ['integritysetup-pre.target',           'HAVE_LIBCRYPTSETUP'],
        ['integritysetup.target',               'HAVE_LIBCRYPTSETUP',
         'sysinit.target.wants/'],
        ['dev-hugepages.mount',                 '',
         'sysinit.target.wants/'],
        ['dev-mqueue.mount',                    '',
         'sysinit.target.wants/'],
        ['emergency.target',                    ''],
        ['exit.target',                         ''],
        ['factory-reset.target',                ''],
        ['final.target',                        ''],
        ['first-boot-complete.target',          ''],
        ['getty.target',                        '',
         'multi-user.target.wants/'],
        ['getty-pre.target',                    ''],
        ['graphical.target',                    '',
         'default.target' + (with_runlevels ? ' runlevel5.target' : '')],
        ['halt.target',                         ''],
        ['hibernate.target',                    'ENABLE_HIBERNATE'],
        ['hybrid-sleep.target',                 'ENABLE_HIBERNATE'],
        ['suspend-then-hibernate.target',       'ENABLE_HIBERNATE'],
        ['initrd-cleanup.service',              'ENABLE_INITRD'],
        ['initrd-fs.target',                    'ENABLE_INITRD'],
        ['initrd-root-device.target',           'ENABLE_INITRD'],
        ['initrd-root-fs.target',               'ENABLE_INITRD'],
        ['initrd-switch-root.service',          'ENABLE_INITRD'],
        ['initrd-switch-root.target',           'ENABLE_INITRD'],
        ['initrd-udevadm-cleanup-db.service',   'ENABLE_INITRD'],
        ['initrd-usr-fs.target',                'ENABLE_INITRD'],
        ['initrd.target',                       'ENABLE_INITRD'],
        ['kexec.target',                        ''],
        ['ldconfig.service',                    'ENABLE_LDCONFIG',
         'sysinit.target.wants/'],
        ['local-fs-pre.target',                 ''],
        ['local-fs.target',                     ''],
        ['machine.slice',                       'ENABLE_MACHINED'],
        ['machines.target',                     'ENABLE_MACHINED'],
        ['modprobe@.service',                   ''],
        ['multi-user.target',                   '',
         (with_runlevels ? 'runlevel2.target runlevel3.target runlevel4.target' : '')],
        ['network-online.target',               ''],
        ['network-pre.target',                  ''],
        ['network.target',                      ''],
        ['nss-lookup.target',                   ''],
        ['nss-user-lookup.target',              ''],
        ['paths.target',                        ''],
        ['poweroff.target',                     '',
         (with_runlevels ? 'runlevel0.target' : '')],
        ['printer.target',                      ''],
        ['proc-sys-fs-binfmt_misc.automount',   'ENABLE_BINFMT',
         'sysinit.target.wants/'],
        ['proc-sys-fs-binfmt_misc.mount',       'ENABLE_BINFMT'],
        ['reboot.target',                       '',
         'ctrl-alt-del.target' + (with_runlevels ? ' runlevel6.target' : '')],
        ['remote-cryptsetup.target',            'HAVE_LIBCRYPTSETUP',
         'initrd-root-device.target.wants/'],
        ['remote-veritysetup.target',           'HAVE_LIBCRYPTSETUP',
         'initrd-root-device.target.wants/'],
        ['remote-fs-pre.target',                ''],
        ['remote-fs.target',                    ''],
        ['rescue.target',                       '',
         (with_runlevels ? 'runlevel1.target' : '')],
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
        ['sys-kernel-tracing.mount',            '',
         'sysinit.target.wants/'],
        ['sysinit.target',                      ''],
        ['syslog.socket',                       ''],
        ['system-systemd\\x2dcryptsetup.slice', 'HAVE_LIBCRYPTSETUP'],
        ['system-update.target',                ''],
        ['system-update-pre.target',            ''],
        ['system-update-cleanup.service',       ''],
        ['systemd-ask-password-console.path',   '',
         'sysinit.target.wants/'],
        ['systemd-ask-password-console.service', ''],
        ['systemd-ask-password-wall.path',      '',
         'multi-user.target.wants/'],
        ['systemd-ask-password-wall.service',   ''],
        ['systemd-boot-system-token.service',   'HAVE_GNU_EFI',
         'sysinit.target.wants/'],
        ['systemd-boot-update.service',         'HAVE_GNU_EFI'],
        ['systemd-coredump.socket',             'ENABLE_COREDUMP',
         'sockets.target.wants/'],
        ['systemd-exit.service',                ''],
        ['systemd-firstboot.service',           'ENABLE_FIRSTBOOT',
         'sysinit.target.wants/'],
        ['systemd-halt.service',                ''],
        ['systemd-homed-activate.service',      'ENABLE_HOMED'],
        ['systemd-initctl.socket',              'HAVE_SYSV_COMPAT',
         'sockets.target.wants/'],
        ['systemd-journal-catalog-update.service', '',
         'sysinit.target.wants/'],
        ['systemd-journal-flush.service',       '',
         'sysinit.target.wants/'],
        ['systemd-journal-gatewayd.socket',     'ENABLE_REMOTE HAVE_MICROHTTPD'],
        ['systemd-journal-remote.socket',       'ENABLE_REMOTE HAVE_MICROHTTPD'],
        ['systemd-journald-audit.socket',       '',
         'sockets.target.wants/'],
        ['systemd-journald-dev-log.socket',     '',
         'sockets.target.wants/'],
        ['systemd-journald.socket',             '',
         'sockets.target.wants/'],
        ['systemd-kexec.service',               ''],
        ['systemd-machine-id-commit.service',   '',
         'sysinit.target.wants/'],
        ['systemd-journald@.socket',            ''],
        ['systemd-journald-varlink@.socket',    ''],
        ['systemd-networkd.socket',             'ENABLE_NETWORKD'],
        ['systemd-poweroff.service',            ''],
        ['systemd-reboot.service',              ''],
        ['systemd-rfkill.socket',               'ENABLE_RFKILL'],
        ['systemd-sysext.service',              'ENABLE_SYSEXT'],
        ['systemd-sysupdate.timer',             'ENABLE_SYSUPDATE'],
        ['systemd-sysupdate-reboot.timer',      'ENABLE_SYSUPDATE'],
        ['systemd-sysusers.service',            'ENABLE_SYSUSERS',
         'sysinit.target.wants/'],
        ['systemd-tmpfiles-clean.service',      'ENABLE_TMPFILES'],
        ['systemd-tmpfiles-clean.timer',        'ENABLE_TMPFILES',
         'timers.target.wants/'],
        ['systemd-tmpfiles-setup-dev.service',  'ENABLE_TMPFILES',
         'sysinit.target.wants/'],
        ['systemd-tmpfiles-setup.service',      'ENABLE_TMPFILES',
         'sysinit.target.wants/'],
        ['systemd-udevd-control.socket',        '',
         'sockets.target.wants/'],
        ['systemd-udev-settle.service',         ''],
        ['systemd-udev-trigger.service',        '',
         'sysinit.target.wants/'],
        ['systemd-udevd-kernel.socket',         '',
         'sockets.target.wants/'],
        ['systemd-userdbd.socket',              'ENABLE_USERDB'],
        ['time-set.target',                     ''],
        ['time-sync.target',                    ''],
        ['timers.target',                       ''],
        ['tmp.mount',                           '',
         'local-fs.target.wants/'],
        ['umount.target',                       ''],
        ['usb-gadget.target',                   ''],
        ['user.slice',                          ''],
        ['var-lib-machines.mount',              'ENABLE_MACHINED',
         'remote-fs.target.wants/ machines.target.wants/'],
        ['systemd-oomd.socket',                 'ENABLE_OOMD'],
]

in_units = [
        ['console-getty.service',                ''],
        ['container-getty@.service',             ''],
        ['debug-shell.service',                  ''],
        ['emergency.service',                    ''],
        ['getty@.service',                       '',
         'autovt@.service'],
        ['initrd-parse-etc.service',             'ENABLE_INITRD'],
        ['kmod-static-nodes.service',            'HAVE_KMOD ENABLE_TMPFILES',
         'sysinit.target.wants/'],
        ['quotaon.service',                      'ENABLE_QUOTACHECK'],
        ['rc-local.service',                     'HAVE_SYSV_COMPAT'],
        ['rescue.service',                       ''],
        ['serial-getty@.service',                ''],
        ['systemd-backlight@.service',           'ENABLE_BACKLIGHT'],
        ['systemd-binfmt.service',               'ENABLE_BINFMT',
         'sysinit.target.wants/'],
        ['systemd-bless-boot.service',           'HAVE_GNU_EFI HAVE_BLKID'],
        ['systemd-boot-check-no-failures.service', ''],
        ['systemd-coredump@.service',            'ENABLE_COREDUMP'],
        ['systemd-pstore.service',               'ENABLE_PSTORE'],
        ['systemd-fsck-root.service',            ''],
        ['systemd-fsck@.service',                ''],
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
        ['systemd-initctl.service',              'HAVE_SYSV_COMPAT'],
        ['systemd-journal-gatewayd.service',     'ENABLE_REMOTE HAVE_MICROHTTPD'],
        ['systemd-journal-remote.service',       'ENABLE_REMOTE HAVE_MICROHTTPD'],
        ['systemd-journal-upload.service',       'ENABLE_REMOTE HAVE_LIBCURL'],
        ['systemd-journald.service',             '',
         'sysinit.target.wants/'],
        ['systemd-journald@.service',            ''],
        ['systemd-localed.service',              'ENABLE_LOCALED',
         'dbus-org.freedesktop.locale1.service'],
        ['systemd-logind.service',               'ENABLE_LOGIND',
         'multi-user.target.wants/ dbus-org.freedesktop.login1.service'],
        ['systemd-machined.service',             'ENABLE_MACHINED',
         'dbus-org.freedesktop.machine1.service'],
        ['systemd-modules-load.service',         'HAVE_KMOD',
         'sysinit.target.wants/'],
        ['systemd-network-generator.service',    ''],
        ['systemd-networkd.service',             'ENABLE_NETWORKD'],
        ['systemd-networkd-wait-online.service', 'ENABLE_NETWORKD'],
        ['systemd-networkd-wait-online@.service','ENABLE_NETWORKD'],
        ['systemd-nspawn@.service',              ''],
        ['systemd-oomd.service',                 'ENABLE_OOMD'],
        ['systemd-portabled.service',            'ENABLE_PORTABLED',
         'dbus-org.freedesktop.portable1.service'],
        ['systemd-userdbd.service',              'ENABLE_USERDB'],
        ['systemd-homed.service',                'ENABLE_HOMED'],
        ['systemd-quotacheck.service',           'ENABLE_QUOTACHECK'],
        ['systemd-random-seed.service',          'ENABLE_RANDOMSEED',
         'sysinit.target.wants/'],
        ['systemd-remount-fs.service',           ''],
        ['systemd-resolved.service',             'ENABLE_RESOLVE'],
        ['systemd-rfkill.service',               'ENABLE_RFKILL'],
        ['systemd-suspend.service',              ''],
        ['systemd-sysctl.service',               '',
         'sysinit.target.wants/'],
        ['systemd-sysupdate.service',            'ENABLE_SYSUPDATE'],
        ['systemd-sysupdate-reboot.service',     'ENABLE_SYSUPDATE'],
        ['systemd-timedated.service',            'ENABLE_TIMEDATED',
         'dbus-org.freedesktop.timedate1.service'],
        ['systemd-timesyncd.service',            'ENABLE_TIMESYNCD'],
        ['systemd-time-wait-sync.service',       'ENABLE_TIMESYNCD'],
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
        ['systemd-volatile-root.service',        'ENABLE_INITRD'],
        ['systemd-repart.service',               'ENABLE_REPART',
         'sysinit.target.wants/ initrd-root-fs.target.wants/'],
        ['user-runtime-dir@.service',            ''],
        ['user@.service',                        ''],
        ['systemd-pcrphase-initrd.service',      'HAVE_GNU_EFI HAVE_OPENSSL HAVE_TPM2 ENABLE_INITRD',
         'initrd.target.wants/'],
        ['systemd-pcrphase-sysinit.service',     'HAVE_GNU_EFI HAVE_OPENSSL HAVE_TPM2',
         'sysinit.target.wants/'],
        ['systemd-pcrphase.service',             'HAVE_GNU_EFI HAVE_OPENSSL HAVE_TPM2',
         'sysinit.target.wants/'],
]

add_wants = []

foreach tuple : in_units
        file = tuple[0]

        # we do this here because install_data does not accept custom_target output
        conds = tuple[1].split(' ')
        install = ((conds.get(0, '') == '' or conf.get(conds[0]) == 1) and
                   (conds.get(1, '') == '' or conf.get(conds[1]) == 1))

        custom_target(
                file,
                input : file + '.in',
                output : file,
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : install,
                install_dir : systemunitdir)

        if install and tuple.length() > 2
                foreach target : tuple[2].split()
                        add_wants += [systemunitdir, target, file]
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
                                add_wants += [systemunitdir, target, file]
                        endforeach
                endif
        endif
endforeach

meson.add_install_script('meson-add-wants.sh', add_wants)

install_data('user-.slice.d/10-defaults.conf',
             install_dir : systemunitdir + '/user-.slice.d')

install_data('user@.service.d/10-login-barrier.conf',
             install_dir : systemunitdir + '/user@.service.d')
install_data('user@0.service.d/10-login-barrier.conf',
             install_dir : systemunitdir + '/user@0.service.d')

############################################################

if install_sysconfdir
        meson.add_install_script(meson_make_symlink,
                                 pkgsysconfdir / 'user',
                                 sysconfdir / 'xdg/systemd/user')
endif
meson.add_install_script(meson_make_symlink,
                         dbussystemservicedir / 'org.freedesktop.systemd1.service',
                         dbussessionservicedir / 'org.freedesktop.systemd1.service')
if conf.get('HAVE_SYSV_COMPAT') == 1
        foreach i : [1, 2, 3, 4, 5]
                meson.add_install_script(
                        'sh', '-c',
                        mkdir_p.format(systemunitdir / 'runlevel@0@.target.wants'.format(i)))
        endforeach
endif

subdir('user')
