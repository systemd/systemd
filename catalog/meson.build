# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2017 Zbigniew Jędrzejewski-Szmek
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

in_files = '''
        systemd.bg.catalog
        systemd.be.catalog
        systemd.be@latin.catalog
        systemd.de.catalog
        systemd.fr.catalog
        systemd.it.catalog
        systemd.pl.catalog
        systemd.pt_BR.catalog
        systemd.ru.catalog
        systemd.zh_CN.catalog
        systemd.zh_TW.catalog
        systemd.catalog
'''.split()

support_url = get_option('support-url')
support_sed = 's~%SUPPORT_URL%~@0@~'.format(support_url)
build_catalog_dir = meson.current_build_dir()

foreach file : in_files
        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [sed, support_sed, '@INPUT@'],
                capture : true,
                install : true,
                install_dir : catalogdir)
endforeach

meson.add_install_script('sh', '-c',
                         'test -n "$DESTDIR" || @0@/journalctl --update-catalog'
                         .format(rootbindir))
