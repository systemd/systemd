# -*- mode: meson -*-

units = [
  ['basic.target',                        ''],
  ['bluetooth.target',                    ''],
  ['cryptsetup-pre.target',               'HAVE_LIBCRYPTSETUP'],
  ['cryptsetup.target',                   'HAVE_LIBCRYPTSETUP'],
  ['dev-hugepages.mount',                 ''],
  ['dev-mqueue.mount',                    ''],
  ['emergency.target',                    ''],
  ['exit.target',                         ''],
  ['final.target',                        ''],
  ['getty.target',                        ''],
  ['graphical.target',                    ''],
  ['halt.target',                         ''],
  ['hibernate.target',                    'ENABLE_HIBERNATE'],
  ['hybrid-sleep.target',                 'ENABLE_HIBERNATE'],
  ['initrd-fs.target',                    ''],
  ['initrd-root-device.target',           ''],
  ['initrd-root-fs.target',               ''],
  ['initrd-switch-root.target',           ''],
  ['initrd.target',                       ''],
  ['kexec.target',                        ''],
  ['ldconfig.service',                    'ENABLE_LDCONFIG'],
  ['local-fs-pre.target',                 ''],
  ['local-fs.target',                     ''],
  ['machine.slice',                       'ENABLE_MACHINED'],
  ['machines.target',                     'ENABLE_MACHINED'],
  ['multi-user.target',                   ''],
  ['network-online.target',               ''],
  ['network-pre.target',                  ''],
  ['network.target',                      ''],
  ['nss-lookup.target',                   ''],
  ['nss-user-lookup.target',              ''],
  ['paths.target',                        ''],
  ['poweroff.target',                     ''],
  ['printer.target',                      ''],
  ['proc-sys-fs-binfmt_misc.automount',   'ENABLE_BINFMT'],
  ['proc-sys-fs-binfmt_misc.mount',       'ENABLE_BINFMT'],
  ['reboot.target',                       ''],
  ['remote-fs-pre.target',                ''],
  ['remote-fs.target',                    ''],
  ['rescue.target',                       ''],
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
  ['sys-fs-fuse-connections.mount',       ''],
  ['sys-kernel-config.mount',             ''],
  ['sys-kernel-debug.mount',              ''],
  ['sysinit.target',                      ''],
  ['syslog.socket',                       ''],
  ['system-update.target',                ''],
  ['system.slice',                        ''],
  ['systemd-ask-password-console.path',   ''],
  ['systemd-ask-password-wall.path',      ''],
  ['systemd-coredump.socket',             'ENABLE_COREDUMP'],
  ['systemd-initctl.socket',              ''],
  ['systemd-journal-gatewayd.socket',     ''],
  ['systemd-journal-remote.socket',       ''],
  ['systemd-journald-audit.socket',       ''],
  ['systemd-journald-dev-log.socket',     ''],
  ['systemd-journald.socket',             ''],
  ['systemd-networkd.socket',             ''],
  ['systemd-rfkill.socket',               'ENABLE_RFKILL'],
  ['systemd-tmpfiles-clean.timer',        ''],
  ['systemd-udevd-control.socket',        ''],
  ['systemd-udevd-kernel.socket',         ''],
  ['time-sync.target',                    ''],
  ['timers.target',                       ''],
  ['umount.target',                       ''],
  ['user.slice',                          ''],
  ['var-lib-machines.mount',              ''],
  ]

foreach pair : units
  if pair[1] == '' or conf.get(pair[1], 0) == 1
    install_data(pair[0],
                 install_dir : systemunitdir)
  endif
endforeach

in_units = [
  ['debug-shell.service',                  ''],
  ['emergency.service',                    ''],
  ['halt-local.service',                   'HAVE_SYSV_COMPAT'],
  ['initrd-cleanup.service',               ''],
  ['initrd-parse-etc.service',             ''],
  ['initrd-switch-root.service',           ''],
  ['initrd-udevadm-cleanup-db.service',    ''],
  ['kmod-static-nodes.service',            'HAVE_KMOD ENABLE_TMPFILES'],
  ['quotaon.service',                      'ENABLE_QUOTACHECK'],
  ['rc-local.service',                     'HAVE_SYSV_COMPAT'],
  ['rescue.service',                       ''],
  ['system-update-cleanup.service',        ''],
  ['systemd-ask-password-console.service', ''],
  ['systemd-ask-password-wall.service',    ''],
  ['systemd-backlight@.service',           'ENABLE_BACKLIGHT'],
  ['systemd-binfmt.service',               'ENABLE_BINFMT'],
  ['systemd-coredump@.service',            'ENABLE_COREDUMP'],
  ['systemd-exit.service',                 ''],
  ['systemd-firstboot.service',            'ENABLE_FIRSTBOOT'],
  ['systemd-fsck-root.service',            ''],
  ['systemd-fsck@.service',                ''],
  ['systemd-halt.service',                 ''],
  ['systemd-hibernate-resume@.service',    'ENABLE_HIBERNATE'],
  ['systemd-hibernate.service',            'ENABLE_HIBERNATE'],
  ['systemd-hybrid-sleep.service',         'ENABLE_HIBERNATE'],
  ['systemd-hostnamed.service',            'ENABLE_HOSTNAMED'],
  ['systemd-hwdb-update.service',          'ENABLE_HWDB'],
  ['systemd-importd.service',              'ENABLE_IMPORTD'],
  ['systemd-initctl.service',               ''],
  ['systemd-journal-catalog-update.service', ''],
  ['systemd-journal-flush.service',         ''],
  ['systemd-journal-gatewayd.service',     'ENABLE_REMOTE HAVE_MICROHTTPD'],
  ['systemd-journal-remote.service',       'ENABLE_REMOTE HAVE_MICROHTTPD'],
  ['systemd-journal-upload.service',       'ENABLE_REMOTE HAVE_LIBCURL'],
  ['systemd-journald.service',             ''],
  ['systemd-kexec.service',                ''],
  ['systemd-localed.service',              'ENABLE_LOCALED'],
  ['systemd-logind.service',               'ENABLE_LOGIND'],
  ['systemd-machine-id-commit.service',    ''],
  ['systemd-machined.service',             'ENABLE_MACHINED'],
  ['systemd-modules-load.service',         'HAVE_KMOD'],
  ['systemd-networkd-wait-online.service', 'ENABLE_NETWORKD'],
  ['systemd-nspawn@.service',              ''],
  ['systemd-poweroff.service',             ''],
  ['systemd-quotacheck.service',           'ENABLE_QUOTACHECK'],
  ['systemd-random-seed.service',          'ENABLE_RANDOMSEED'],
  ['systemd-reboot.service',               ''],
  ['systemd-remount-fs.service',           ''],
  ['systemd-rfkill.service',               'ENABLE_RFKILL'],
  ['systemd-suspend.service',              ''],
  ['systemd-sysctl.service',               ''],
  ['systemd-sysusers.service',             'ENABLE_SYSUSERS'],
  ['systemd-timedated.service',            'ENABLE_TIMEDATED'],
  ['systemd-timesyncd.service',            'ENABLE_TIMESYNCD'],
  ['systemd-tmpfiles-clean.service',       'ENABLE_TMPFILES'],
  ['systemd-tmpfiles-setup-dev.service',   'ENABLE_TMPFILES'],
  ['systemd-tmpfiles-setup.service',       'ENABLE_TMPFILES'],
  ['systemd-udev-settle.service',          ''],
  ['systemd-udev-trigger.service',         ''],
  ['systemd-udevd.service',                ''],
  ['systemd-update-done.service',          ''],
  ['systemd-update-utmp-runlevel.service', 'HAVE_UTMP HAVE_SYSV_COMPAT'],
  ['systemd-update-utmp.service',          'HAVE_UTMP'],
  ['systemd-user-sessions.service',        ''],
  ['systemd-vconsole-setup.service',       'ENABLE_VCONSOLE'],
  ['systemd-volatile-root.service',        ''],
  ]

foreach pair : in_units
  file = pair[0]
  conds = pair[1].split(' ')
  install = ((conds.get(0, '') == '' or conf.get(conds[0], 0) == 1) and
             (conds.get(1, '') == '' or conf.get(conds[1], 0) == 1))

  gen = configure_file(
      input : file + '.in',
      output : file,
      configuration : substs)
  if install
    install_data(gen,
                 install_dir : systemunitdir)
  endif
endforeach

m4_units = [
  ['getty@.service',                     ''],
  ['serial-getty@.service',              ''],
  ['tmp.mount',                          ''],
  ]

foreach pair : m4_units
  file = pair[0]
  install = pair[1] == '' or conf.get(pair[1], 0) == 1

  custom_target(
    file,
    input : file + '.m4',
    output: file,
    command : [m4, '-P'] + m4_defines + ['@INPUT@'],
    capture : true,
    install : install,
    install_dir : systemunitdir)
endforeach

m4_in_units = [
  ['console-getty.service',              ''],
  ['container-getty@.service',           ''],
  ['systemd-networkd.service',           'ENABLE_NETWORKD'],
  ['systemd-resolved.service',           'ENABLE_RESOLVED'],
  ['user@.service',                      ''],
  ]

foreach pair : m4_in_units
  file = pair[0]
  install = pair[1] == '' or conf.get(pair[1], 0) == 1

  gen = configure_file(
      input : file + '.m4.in',
      output : file + '.m4',
      configuration : substs)

  custom_target(
    file,
    input : gen,
    output: file,
    command : [m4, '-P'] + m4_defines + ['@INPUT@'],
    capture : true,
    install : install,
    install_dir : systemunitdir)
endforeach

subdir('user')
