# SPDX-License-Identifier: LGPL-2.1-or-later

configure_file(
        input : 'macros.systemd.in',
        output : 'macros.systemd',
        configuration : substs,
        install_dir : rpmmacrosdir == 'no' ? '' : rpmmacrosdir)

configure_file(
        input : 'triggers.systemd.in',
        output : 'triggers.systemd',
        configuration : substs)
# This doesn't get installed anywhere, it needs to included in the rpm spec
# file definition.
