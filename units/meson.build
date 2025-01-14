# SPDX-License-Identifier: LGPL-2.1-or-later

with_runlevels = conf.get('HAVE_SYSV_COMPAT') == 1

units = [
        { 'file' : 'basic.target' },
        { 'file' : 'blockdev@.target' },
        { 'file' : 'bluetooth.target' },
        { 'file' : 'boot-complete.target' },
        { 'file' : 'breakpoint-pre-basic.service.in' },
        { 'file' : 'breakpoint-pre-mount.service.in' },
        { 'file' : 'breakpoint-pre-switch-root.service.in' },
        { 'file' : 'breakpoint-pre-udev.service.in' },
        { 'file' : 'capsule@.service.in' },
        { 'file' : 'capsule.slice' },
        { 'file' : 'console-getty.service.in' },
        { 'file' : 'container-getty@.service.in' },
        {
          'file' : 'cryptsetup-pre.target',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
        },
        {
          'file' : 'cryptsetup.target',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        { 'file' : 'debug-shell.service.in' },
        {
          'file' : 'dev-hugepages.mount',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'dev-mqueue.mount',
          'symlinks' : ['sysinit.target.wants/'],
        },
        { 'file' : 'emergency.service.in' },
        { 'file' : 'emergency.target' },
        { 'file' : 'exit.target' },
        { 'file' : 'factory-reset.target' },
        { 'file' : 'final.target' },
        { 'file' : 'first-boot-complete.target' },
        { 'file' : 'getty-pre.target' },
        {
          'file' : 'getty.target',
          'symlinks' : ['multi-user.target.wants/'],
        },
        {
          'file' : 'getty@.service.in',
          'symlinks' : ['autovt@.service'],
        },
        {
          'file' : 'graphical.target',
          'symlinks' : ['default.target'] + (with_runlevels ? ['runlevel5.target'] : []),
        },
        { 'file' : 'halt.target' },
        {
          'file' : 'hibernate.target',
          'conditions' : ['ENABLE_HIBERNATE'],
        },
        {
          'file' : 'hybrid-sleep.target',
          'conditions' : ['ENABLE_HIBERNATE'],
        },
        {
          'file' : 'systemd-battery-check.service.in',
          'conditions' : ['ENABLE_INITRD'],
          'symlinks' : ['initrd.target.wants/'],
        },
        {
          'file' : 'systemd-bsod.service.in',
          'conditions' : ['HAVE_QRENCODE', 'ENABLE_INITRD'],
          'symlinks' : ['initrd.target.wants/'],
        },
        {
          'file' : 'initrd-cleanup.service',
          'conditions' : ['ENABLE_INITRD'],
        },
        {
          'file' : 'initrd-fs.target',
          'conditions' : ['ENABLE_INITRD'],
        },
        {
          'file' : 'initrd-parse-etc.service.in',
          'conditions' : ['ENABLE_INITRD'],
        },
        {
          'file' : 'initrd-root-device.target',
          'conditions' : ['ENABLE_INITRD'],
        },
        {
          'file' : 'initrd-root-fs.target',
          'conditions' : ['ENABLE_INITRD'],
        },
        {
          'file' : 'initrd-switch-root.service',
          'conditions' : ['ENABLE_INITRD'],
        },
        {
          'file' : 'initrd-switch-root.target',
          'conditions' : ['ENABLE_INITRD'],
        },
        {
          'file' : 'initrd-udevadm-cleanup-db.service',
          'conditions' : ['ENABLE_INITRD'],
          'install_tag' : 'udev',
        },
        {
          'file' : 'initrd-usr-fs.target',
          'conditions' : ['ENABLE_INITRD'],
        },
        {
          'file' : 'initrd.target',
          'conditions' : ['ENABLE_INITRD'],
        },
        {
          'file' : 'integritysetup-pre.target',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
        },
        {
          'file' : 'integritysetup.target',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        { 'file' : 'kexec.target' },
        {
          'file' : 'kmod-static-nodes.service.in',
          'conditions' : ['HAVE_KMOD', 'ENABLE_TMPFILES'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'ldconfig.service',
          'conditions' : ['ENABLE_LDCONFIG'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        { 'file' : 'local-fs-pre.target' },
        { 'file' : 'local-fs.target' },
        {
          'file' : 'machine.slice',
          'conditions' : ['ENABLE_MACHINED'],
        },
        {
          'file' : 'machines.target',
          'conditions' : ['ENABLE_MACHINED'],
        },
        { 'file' : 'modprobe@.service' },
        {
          'file' : 'multi-user.target',
          'symlinks' : with_runlevels ? ['runlevel2.target', 'runlevel3.target', 'runlevel4.target'] : [],
        },
        { 'file' : 'network-online.target' },
        { 'file' : 'network-pre.target' },
        { 'file' : 'network.target' },
        { 'file' : 'nss-lookup.target' },
        { 'file' : 'nss-user-lookup.target' },
        { 'file' : 'paths.target' },
        {
          'file' : 'poweroff.target',
          'symlinks' : with_runlevels ? ['runlevel0.target'] : [],
        },
        { 'file' : 'printer.target' },
        {
          'file' : 'proc-sys-fs-binfmt_misc.automount',
          'conditions' : ['ENABLE_BINFMT'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'proc-sys-fs-binfmt_misc.mount',
          'conditions' : ['ENABLE_BINFMT'],
        },
        {
          'file' : 'quotaon@.service.in',
          'conditions' : ['ENABLE_QUOTACHECK'],
        },
        {
          'file' : 'quotaon-root.service.in',
          'conditions' : ['ENABLE_QUOTACHECK'],
        },
        {
          'file' : 'rc-local.service.in',
          'conditions' : ['HAVE_SYSV_COMPAT'],
        },
        {
          'file' : 'reboot.target',
          'symlinks' : ['ctrl-alt-del.target'] + (with_runlevels ? ['runlevel6.target'] : []),
        },
        {
          'file' : 'remote-cryptsetup.target',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
          'symlinks' : ['initrd-root-device.target.wants/'],
        },
        { 'file' : 'remote-fs-pre.target' },
        { 'file' : 'remote-fs.target' },
        {
          'file' : 'remote-veritysetup.target',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
          'symlinks' : ['initrd-root-device.target.wants/'],
        },
        { 'file' : 'rescue.service.in' },
        {
          'file' : 'rescue.target',
          'symlinks' : with_runlevels ? ['runlevel1.target'] : [],
        },
        { 'file' : 'rpcbind.target' },
        { 'file' : 'serial-getty@.service.in' },
        { 'file' : 'shutdown.target' },
        { 'file' : 'sigpwr.target' },
        { 'file' : 'sleep.target' },
        { 'file' : 'slices.target' },
        { 'file' : 'smartcard.target' },
        { 'file' : 'sockets.target' },
        { 'file' : 'soft-reboot.target' },
        { 'file' : 'sound.target' },
        { 'file' : 'ssh-access.target' },
        {
          'file' : 'suspend-then-hibernate.target',
          'conditions' : ['ENABLE_HIBERNATE'],
        },
        { 'file' : 'suspend.target' },
        { 'file' : 'swap.target' },
        {
          'file' : 'sys-fs-fuse-connections.mount',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'sys-kernel-config.mount',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'sys-kernel-debug.mount',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'sys-kernel-tracing.mount',
          'symlinks' : ['sysinit.target.wants/'],
        },
        { 'file' : 'sysinit.target' },
        { 'file' : 'syslog.socket' },
        {
          'file' : 'system-systemd\\x2dcryptsetup.slice',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
        },
        {
          'file' : 'system-systemd\\x2dveritysetup.slice',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
        },
        { 'file' : 'system-update-cleanup.service' },
        { 'file' : 'system-update-pre.target' },
        { 'file' : 'system-update.target' },
        {
          'file' : 'systemd-ask-password.socket',
          'symlinks' : ['sockets.target.wants/']
        },
        { 'file' : 'systemd-ask-password@.service' },
        {
          'file' : 'systemd-ask-password-console.path',
          'symlinks' : ['sysinit.target.wants/'],
        },
        { 'file' : 'systemd-ask-password-console.service' },
        {
          'file' : 'systemd-ask-password-wall.path',
          'symlinks' : ['multi-user.target.wants/'],
        },
        { 'file' : 'systemd-ask-password-wall.service' },
        {
          'file' : 'systemd-backlight@.service.in',
          'conditions' : ['ENABLE_BACKLIGHT'],
        },
        {
          'file' : 'systemd-binfmt.service.in',
          'conditions' : ['ENABLE_BINFMT'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-bless-boot.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_BLKID'],
        },
        { 'file' : 'systemd-boot-check-no-failures.service.in' },
        {
          'file' : 'systemd-boot-random-seed.service',
          'conditions' : ['ENABLE_BOOTLOADER'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-boot-update.service',
          'conditions' : ['ENABLE_BOOTLOADER'],
        },
        {
          'file' : 'systemd-bootctl@.service',
          'conditions' : ['ENABLE_BOOTLOADER'],
        },
        {
          'file' : 'systemd-bootctl.socket',
          'conditions' : ['ENABLE_BOOTLOADER'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-confext.service',
          'conditions' : ['ENABLE_SYSEXT'],
        },
        {
          'file' : 'systemd-confext-initrd.service',
          'conditions' : ['ENABLE_INITRD', 'ENABLE_SYSEXT'],
          'symlinks' : ['initrd.target.wants/'],
        },
        {
          'file' : 'systemd-coredump.socket',
          'conditions' : ['ENABLE_COREDUMP'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-coredump@.service.in',
          'conditions' : ['ENABLE_COREDUMP'],
        },
        {
          'file' : 'systemd-creds.socket',
          'symlinks' : ['sockets.target.wants/'],
        },
        { 'file' : 'systemd-creds@.service' },
        { 'file' : 'systemd-exit.service' },
        {
          'file' : 'systemd-firstboot.service',
          'conditions' : ['ENABLE_FIRSTBOOT'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        { 'file' : 'systemd-fsck-root.service.in' },
        { 'file' : 'systemd-fsck@.service.in' },
        { 'file' : 'systemd-growfs-root.service.in' },
        { 'file' : 'systemd-growfs@.service.in' },
        { 'file' : 'systemd-halt.service' },
        {
          'file' : 'systemd-hibernate-clear.service.in',
          'conditions' : ['ENABLE_HIBERNATE', 'ENABLE_EFI'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-hibernate-resume.service.in',
          'conditions' : ['ENABLE_HIBERNATE'],
        },
        {
          'file' : 'systemd-hibernate.service.in',
          'conditions' : ['ENABLE_HIBERNATE'],
        },
        {
          'file' : 'systemd-homed-activate.service',
          'conditions' : ['ENABLE_HOMED'],
        },
        {
          'file' : 'systemd-homed-firstboot.service',
          'conditions' : ['ENABLE_HOMED'],
        },
        {
          'file' : 'systemd-homed.service.in',
          'conditions' : ['ENABLE_HOMED'],
        },
        {
          'file' : 'systemd-hostnamed.service.in',
          'conditions' : ['ENABLE_HOSTNAMED'],
          'symlinks' : ['dbus-org.freedesktop.hostname1.service'],
        },
        {
          'file' : 'systemd-hostnamed.socket',
          'conditions' : ['ENABLE_HOSTNAMED'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-hwdb-update.service.in',
          'conditions' : ['ENABLE_HWDB'],
          'symlinks' : ['sysinit.target.wants/'],
          'install_tag' : 'hwdb',
        },
        {
          'file' : 'systemd-hybrid-sleep.service.in',
          'conditions' : ['ENABLE_HIBERNATE'],
        },
        {
          'file' : 'systemd-importd.service.in',
          'conditions' : ['ENABLE_IMPORTD'],
          'symlinks' : ['dbus-org.freedesktop.import1.service'],
        },
        {
          'file' : 'systemd-importd.socket',
          'conditions' : ['ENABLE_IMPORTD'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-initctl.service.in',
          'conditions' : ['HAVE_SYSV_COMPAT'],
        },
        {
          'file' : 'systemd-initctl.socket',
          'conditions' : ['HAVE_SYSV_COMPAT'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-journal-catalog-update.service',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-journal-flush.service',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-journal-gatewayd.service.in',
          'conditions' : ['ENABLE_REMOTE', 'HAVE_MICROHTTPD'],
        },
        {
          'file' : 'systemd-journal-gatewayd.socket',
          'conditions' : ['ENABLE_REMOTE', 'HAVE_MICROHTTPD'],
        },
        {
          'file' : 'systemd-journal-remote.service.in',
          'conditions' : ['ENABLE_REMOTE', 'HAVE_MICROHTTPD'],
        },
        {
          'file' : 'systemd-journal-remote.socket',
          'conditions' : ['ENABLE_REMOTE', 'HAVE_MICROHTTPD'],
        },
        {
          'file' : 'systemd-journal-upload.service.in',
          'conditions' : ['ENABLE_REMOTE', 'HAVE_LIBCURL'],
        },
        { 'file' : 'systemd-journald-audit.socket' },
        {
          'file' : 'systemd-journald-dev-log.socket',
          'symlinks' : ['sockets.target.wants/'],
        },
        { 'file' : 'systemd-journald-sync@.service' },
        { 'file' : 'systemd-journald-varlink@.socket' },
        {
          'file' : 'systemd-journald.service.in',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-journald.socket',
          'symlinks' : ['sockets.target.wants/'],
        },
        { 'file' : 'systemd-journald@.service.in' },
        { 'file' : 'systemd-journald@.socket' },
        { 'file' : 'systemd-kexec.service' },
        {
          'file' : 'systemd-localed.service.in',
          'conditions' : ['ENABLE_LOCALED'],
          'symlinks' : ['dbus-org.freedesktop.locale1.service'],
        },
        {
          'file' : 'systemd-logind.service.in',
          'conditions' : ['ENABLE_LOGIND'],
          'symlinks' : ['multi-user.target.wants/', 'dbus-org.freedesktop.login1.service'],
        },
        {
          'file' : 'systemd-machine-id-commit.service',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-machined.service.in',
          'conditions' : ['ENABLE_MACHINED'],
          'symlinks' : ['dbus-org.freedesktop.machine1.service'],
        },
        {
          'file' : 'systemd-modules-load.service.in',
          'conditions' : ['HAVE_KMOD'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        { 'file' : 'systemd-network-generator.service.in' },
        {
          'file' : 'systemd-networkd-persistent-storage.service',
          'conditions' : ['ENABLE_NETWORKD'],
        },
        {
          'file' : 'systemd-networkd-wait-online.service.in',
          'conditions' : ['ENABLE_NETWORKD'],
        },
        {
          'file' : 'systemd-networkd-wait-online@.service.in',
          'conditions' : ['ENABLE_NETWORKD'],
        },
        {
          'file' : 'systemd-networkd.service.in',
          'conditions' : ['ENABLE_NETWORKD'],
        },
        {
          'file' : 'systemd-networkd.socket',
          'conditions' : ['ENABLE_NETWORKD'],
        },
        { 'file' : 'systemd-nspawn@.service.in' },
        {
          'file' : 'systemd-vmspawn@.service.in',
          'conditions' : ['ENABLE_VMSPAWN'],
        },
        {
          'file' : 'systemd-oomd.service.in',
          'conditions' : ['ENABLE_OOMD'],
        },
        {
          'file' : 'systemd-oomd.socket',
          'conditions' : ['ENABLE_OOMD'],
        },
        {
          'file' : 'systemd-pcrextend@.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrextend.socket',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-pcrfs-root.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrfs@.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrmachine.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-pcrphase-initrd.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2', 'ENABLE_INITRD'],
          'symlinks' : ['initrd.target.wants/'],
        },
        {
          'file' : 'systemd-pcrphase-sysinit.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-pcrphase.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-tpm2-setup.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-tpm2-setup-early.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-pcrlock-make-policy.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrlock-secureboot-policy.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrlock-secureboot-authority.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrlock-file-system.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrlock-machine-id.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrlock-firmware-code.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrlock-firmware-config.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrlock@.service.in',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
        },
        {
          'file' : 'systemd-pcrlock.socket',
          'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_OPENSSL', 'HAVE_TPM2'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-portabled.service.in',
          'conditions' : ['ENABLE_PORTABLED'],
          'symlinks' : ['dbus-org.freedesktop.portable1.service'],
        },
        { 'file' : 'systemd-poweroff.service' },
        {
          'file' : 'systemd-pstore.service.in',
          'conditions' : ['ENABLE_PSTORE'],
        },
        {
          'file' : 'systemd-quotacheck@.service.in',
          'conditions' : ['ENABLE_QUOTACHECK'],
        },
        {
          'file' : 'systemd-quotacheck-root.service.in',
          'conditions' : ['ENABLE_QUOTACHECK'],
        },
        {
          'file' : 'systemd-random-seed.service.in',
          'conditions' : ['ENABLE_RANDOMSEED'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        { 'file' : 'systemd-reboot.service' },
        { 'file' : 'systemd-remount-fs.service.in' },
        {
          'file' : 'systemd-repart.service',
          'conditions' : ['ENABLE_REPART'],
          'symlinks' : ['sysinit.target.wants/', 'initrd-root-fs.target.wants/'],
        },
        {
          'file' : 'systemd-resolved.service.in',
          'conditions' : ['ENABLE_RESOLVE'],
        },
        {
          'file' : 'systemd-rfkill.service.in',
          'conditions' : ['ENABLE_RFKILL'],
        },
        {
          'file' : 'systemd-rfkill.socket',
          'conditions' : ['ENABLE_RFKILL'],
        },
        { 'file' : 'systemd-soft-reboot.service' },
        {
          'file' : 'systemd-suspend-then-hibernate.service.in',
          'conditions' : ['ENABLE_HIBERNATE'],
        },
        { 'file' : 'systemd-suspend.service.in' },
        {
          'file' : 'systemd-sysctl.service.in',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-sysext.service',
          'conditions' : ['ENABLE_SYSEXT'],
        },
        {
          'file' : 'systemd-sysext-initrd.service',
          'conditions' : ['ENABLE_INITRD', 'ENABLE_SYSEXT'],
          'symlinks' : ['initrd.target.wants/'],
        },
        {
          'file' : 'systemd-sysext.socket',
          'conditions' : ['ENABLE_SYSEXT'],
          'symlinks' : ['sockets.target.wants/'],
        },
        {
          'file' : 'systemd-sysext@.service',
          'conditions' : ['ENABLE_SYSEXT'],
        },
        {
          'file' : 'systemd-sysupdate-reboot.service.in',
          'conditions' : ['ENABLE_SYSUPDATE'],
        },
        {
          'file' : 'systemd-sysupdate-reboot.timer',
          'conditions' : ['ENABLE_SYSUPDATE'],
        },
        {
          'file' : 'systemd-sysupdate.service.in',
          'conditions' : ['ENABLE_SYSUPDATE'],
        },
        {
          'file' : 'systemd-sysupdate.timer',
          'conditions' : ['ENABLE_SYSUPDATE'],
        },
        {
          'file' : 'systemd-sysupdated.service.in',
          'conditions' : ['ENABLE_SYSUPDATED'],
          'symlinks' : ['dbus-org.freedesktop.sysupdate1.service'],
        },
        {
          'file' : 'systemd-sysusers.service',
          'conditions' : ['ENABLE_SYSUSERS'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-storagetm.service.in',
          'conditions' : ['ENABLE_STORAGETM'],
        },
        {
          'file' : 'storage-target-mode.target',
          'conditions' : ['ENABLE_STORAGETM'],
        },
        {
          'file' : 'systemd-time-wait-sync.service.in',
          'conditions' : ['ENABLE_TIMESYNCD'],
        },
        {
          'file' : 'systemd-timedated.service.in',
          'conditions' : ['ENABLE_TIMEDATED'],
          'symlinks' : ['dbus-org.freedesktop.timedate1.service'],
        },
        {
          'file' : 'systemd-timesyncd.service.in',
          'conditions' : ['ENABLE_TIMESYNCD'],
        },
        {
          'file' : 'systemd-tmpfiles-clean.service',
          'conditions' : ['ENABLE_TMPFILES'],
        },
        {
          'file' : 'systemd-tmpfiles-clean.timer',
          'conditions' : ['ENABLE_TMPFILES'],
          'symlinks' : ['timers.target.wants/'],
        },
        {
          'file' : 'systemd-tmpfiles-setup-dev-early.service',
          'conditions' : ['ENABLE_TMPFILES'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-tmpfiles-setup-dev.service',
          'conditions' : ['ENABLE_TMPFILES'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-tmpfiles-setup.service',
          'conditions' : ['ENABLE_TMPFILES'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-udev-load-credentials.service',
          'install_tag' : 'udev',
        },
        {
          'file' : 'systemd-udev-settle.service',
          'install_tag' : 'udev',
        },
        {
          'file' : 'systemd-udev-trigger.service',
          'symlinks' : ['sysinit.target.wants/'],
          'install_tag' : 'udev',
        },
        {
          'file' : 'systemd-udevd-control.socket',
          'symlinks' : ['sockets.target.wants/'],
          'install_tag' : 'udev',
        },
        {
          'file' : 'systemd-udevd-kernel.socket',
          'symlinks' : ['sockets.target.wants/'],
          'install_tag' : 'udev',
        },
        {
          'file' : 'systemd-udevd-varlink.socket',
          'symlinks' : ['sockets.target.wants/'],
          'install_tag' : 'udev',
        },
        {
          'file' : 'systemd-udevd.service.in',
          'symlinks' : ['sysinit.target.wants/'],
          'install_tag' : 'udev',
        },
        {
          'file' : 'systemd-update-done.service.in',
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-update-utmp-runlevel.service.in',
          'conditions' : ['ENABLE_UTMP', 'HAVE_SYSV_COMPAT'],
          'symlinks' : ['multi-user.target.wants/', 'graphical.target.wants/', 'rescue.target.wants/'],
        },
        {
          'file' : 'systemd-update-utmp.service.in',
          'conditions' : ['ENABLE_UTMP'],
          'symlinks' : ['sysinit.target.wants/'],
        },
        {
          'file' : 'systemd-user-sessions.service.in',
          'conditions' : ['HAVE_PAM'],
          'symlinks' : ['multi-user.target.wants/'],
        },
        {
          'file' : 'systemd-userdbd.service.in',
          'conditions' : ['ENABLE_USERDB'],
        },
        {
          'file' : 'systemd-userdbd.socket',
          'conditions' : ['ENABLE_USERDB'],
        },
        {
          'file' : 'systemd-mountfsd.service.in',
          'conditions' : ['ENABLE_MOUNTFSD'],
        },
        {
          'file' : 'systemd-mountfsd.socket',
          'conditions' : ['ENABLE_MOUNTFSD'],
        },
        {
          'file' : 'systemd-nsresourced.service.in',
          'conditions' : ['ENABLE_NSRESOURCED'],
        },
        {
          'file' : 'systemd-nsresourced.socket',
          'conditions' : ['ENABLE_NSRESOURCED'],
        },
        {
          'file' : 'systemd-vconsole-setup.service.in',
          'conditions' : ['ENABLE_VCONSOLE'],
        },
        {
          'file' : 'systemd-volatile-root.service.in',
          'conditions' : ['ENABLE_INITRD'],
        },
        { 'file' : 'time-set.target' },
        { 'file' : 'time-sync.target' },
        { 'file' : 'timers.target' },
        {
          'file' : 'tmp.mount',
          'symlinks' : ['local-fs.target.wants/'],
        },
        { 'file' : 'tpm2.target' },
        { 'file' : 'umount.target' },
        { 'file' : 'usb-gadget.target' },
        { 'file' : 'user-runtime-dir@.service.in' },
        { 'file' : 'user.slice' },
        { 'file' : 'user@.service.in' },
        {
          'file' : 'var-lib-machines.mount',
          'conditions' : ['ENABLE_MACHINED'],
          'symlinks' : ['remote-fs.target.wants/', 'machines.target.wants/'],
        },
        {
          'file' : 'veritysetup-pre.target',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
        },
        {
          'file' : 'veritysetup.target',
          'conditions' : ['HAVE_LIBCRYPTSETUP'],
          'symlinks' : ['sysinit.target.wants/'],
        },
]

# For the udev/hwdb aliases
udev_units = []
hwdb_units = []

foreach unit : units
        source = unit.get('file')

        if source.endswith('.in')
                needs_jinja = true
                name = source.substring(0, -3)
                assert(name + '.in' == source)
        else
                needs_jinja = false
                name = source
        endif
        source = files(source)

        install = true
        foreach cond : unit.get('conditions', [])
                if conf.get(cond) != 1
                        install = false
                        break
                endif
        endforeach

        if needs_jinja
                t = custom_target(
                        name,
                        input : source,
                        output : name,
                        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                        install : install,
                        install_dir : systemunitdir,
                        install_tag : unit.get('install_tag', ''))
                if unit.get('install_tag', '') == 'udev'
                        udev_units += t
                elif unit.get('install_tag', '') == 'hwdb'
                        hwdb_units += t
                endif
        elif install
                install_data(source,
                             install_dir : systemunitdir,
                             install_tag : unit.get('install_tag', ''))
        endif

        if install
                foreach target : unit.get('symlinks', [])
                        if target.endswith('/')
                                install_emptydir(systemunitdir / target, install_tag : unit.get('install_tag', ''))
                                meson.add_install_script(sh, '-c',
                                                         ln_s.format(systemunitdir / name,
                                                                     systemunitdir / target / name),
                                                         install_tag : unit.get('install_tag', ''))
                        else
                                meson.add_install_script(sh, '-c',
                                                         ln_s.format(systemunitdir / name,
                                                                     systemunitdir / target),
                                                         install_tag : unit.get('install_tag', ''))
                        endif
                endforeach
        endif
endforeach

install_data('user-.slice.d/10-defaults.conf',
             install_dir : systemunitdir + '/user-.slice.d')

install_data('user@.service.d/10-login-barrier.conf',
             install_dir : systemunitdir + '/user@.service.d')
install_data('user@0.service.d/10-login-barrier.conf',
             install_dir : systemunitdir + '/user@0.service.d')

############################################################

install_emptydir(dbussessionservicedir)
meson.add_install_script(sh, '-c',
                         ln_s.format(dbussystemservicedir / 'org.freedesktop.systemd1.service',
                                     dbussessionservicedir / 'org.freedesktop.systemd1.service'))

if conf.get('HAVE_SYSV_COMPAT') == 1
        foreach i : [1, 2, 3, 4, 5]
                install_emptydir(systemunitdir / 'runlevel@0@.target.wants'.format(i))
        endforeach
endif

subdir('user')
