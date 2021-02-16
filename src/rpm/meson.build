# SPDX-License-Identifier: LGPL-2.1-or-later

configure_file(
        input : 'macros.systemd.in',
        output : 'macros.systemd',
        configuration : substs,
        install_dir : rpmmacrosdir == 'no' ? '' : rpmmacrosdir)

# Those doesn't get installed anywhere, one of them needs to included in the
# rpm spec file definition.
configure_file(
        input : 'triggers.systemd.in',
        output : 'triggers.systemd',
        configuration : substs)
configure_file(
        input : 'triggers.systemd.sh.in',
        output : 'triggers.systemd.sh',
        configuration : substs)
