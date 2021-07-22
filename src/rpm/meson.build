# SPDX-License-Identifier: LGPL-2.1-or-later

in_files = [
        ['macros.systemd',        rpmmacrosdir != 'no', rpmmacrosdir],

        # we conditionalize on rpmmacrosdir, but install into rootlibexecdir
        ['systemd-update-helper', rpmmacrosdir != 'no', rootlibexecdir, 'rwxr-xr-x'],

        ['triggers.systemd',      false],
        ['triggers.systemd.sh',   false]]

# The last two don't get installed anywhere, one of them needs to included in
# the rpm spec file definition instead.

foreach tuple : in_files
        file = tuple[0]
        custom_target(
                file,
                input : file + '.in',
                output : file,
                command : [meson_render_jinja2, config_h, '@INPUT@'],
                capture : true,
                install : tuple[1],
                install_dir : tuple.length() > 2 ? tuple[2] : '',
                install_mode : tuple.length() > 3 ? tuple[3] : false,
                build_by_default : true)
endforeach
