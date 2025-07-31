# SPDX-License-Identifier: LGPL-2.1-or-later

in_files = [
        ['macros.systemd',        rpmmacrosdir != 'no', rpmmacrosdir],

        # we conditionalize on rpmmacrosdir, but install into libexecdir
        ['systemd-update-helper', rpmmacrosdir != 'no', libexecdir],

        ['triggers.systemd',      false],
        ['triggers.systemd.sh',   false]]

# The last two don't get installed anywhere, one of them needs to included in
# the rpm spec file definition instead.

rpm_depends = []

foreach tuple : in_files
        file = tuple[0]
        rpm_depends += custom_target(
                input : file + '.in',
                output : file,
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : tuple[1],
                install_dir : tuple.length() > 2 ? tuple[2] : '',
                build_by_default : true)
endforeach
