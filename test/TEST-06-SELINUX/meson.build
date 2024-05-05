# SPDX-License-Identifier: LGPL-2.1-or-later

test_params += {
        'mkosi_args' : ['--kernel-command-line-extra=apparmor=0 selinux=1 enforcing=0 lsm=selinux systemd.wants=autorelabel.service systemd.wants=firstboot-autorelabel.service'],
        # FIXME; Figure out why reboot sometimes hangs with 'linux' firmware.
        'firmware' : 'uefi',
}
