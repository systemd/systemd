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

hwdb_files = files('''
        20-pci-vendor-model.hwdb
        20-pci-classes.hwdb
        20-usb-vendor-model.hwdb
        20-usb-classes.hwdb
        20-sdio-vendor-model.hwdb
        20-sdio-classes.hwdb
        20-bluetooth-vendor-product.hwdb
        20-acpi-vendor.hwdb
        20-OUI.hwdb
        20-net-ifname.hwdb
        60-evdev.hwdb
        60-keyboard.hwdb
        60-sensor.hwdb
        70-joystick.hwdb
        70-mouse.hwdb
        70-pointingstick.hwdb
        70-touchpad.hwdb
'''.split())

if conf.get('ENABLE_HWDB') == 1
        install_data(hwdb_files,
                     install_dir : udevhwdbdir)

        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(join_paths(sysconfdir, 'udev/hwdb.d')))

        meson.add_install_script('sh', '-c',
                                 'test -n "$DESTDIR" || @0@/systemd-hwdb update'
                                 .format(rootbindir))
endif

############################################################

parse_hwdb_py = find_program('parse_hwdb.py')
test('parse-hwdb',
     parse_hwdb_py,
     timeout : 90)

############################################################

run_target(
        'hwdb-update',
        command : [hwdb_update_sh, meson.current_source_dir()])
