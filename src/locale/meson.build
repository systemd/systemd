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

systemd_localed_sources = files('''
        localed.c
        keymap-util.c
        keymap-util.h
'''.split())

localectl_sources = files('localectl.c')

if conf.get('ENABLE_LOCALED') == 1
        install_data('org.freedesktop.locale1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.locale1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.locale1.policy',
                     install_dir : polkitpolicydir)
endif

# If you know a way that allows the same variables to be used
# in sources list and concatenated to a string for test_env,
# let me know.
kbd_model_map = join_paths(meson.current_source_dir(),  'kbd-model-map')
language_fallback_map = join_paths(meson.current_source_dir(), 'language-fallback-map')

if conf.get('ENABLE_LOCALED') == 1
        install_data('kbd-model-map',
                     'language-fallback-map',
                     install_dir : pkgdatadir)
endif

tests += [
        [['src/locale/test-keymap-util.c',
          'src/locale/keymap-util.c',
          'src/locale/keymap-util.h'],
         [libshared],
         [libdl]],
]
