# SPDX-License-Identifier: LGPL-2.1-or-later

install_data('90-systemd.preset',
             install_dir : systempresetdir)

install_data('90-systemd-user.preset',
             install_dir : userpresetdir,
             rename : '90-systemd.preset')

install_data('90-systemd-initrd.preset',
             install_dir : initrdpresetdir,
             rename : '90-systemd.preset')

install_data('99-default-initrd.preset',
             install_dir : initrdpresetdir,
             rename : '99-default.preset')
