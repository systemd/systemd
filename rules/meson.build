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

rules = files('''
        60-block.rules
        60-cdrom_id.rules
        60-drm.rules
        60-evdev.rules
        60-input-id.rules
        60-persistent-alsa.rules
        60-persistent-input.rules
        60-persistent-storage.rules
        60-persistent-storage-tape.rules
        60-persistent-v4l.rules
        60-sensor.rules
        60-serial.rules
        70-joystick.rules
        70-mouse.rules
        70-touchpad.rules
        75-net-description.rules
        75-probe_mtd.rules
        78-sound-card.rules
        80-drivers.rules
        80-net-setup-link.rules
'''.split())

install_data(rules,
             install_dir : udevrulesdir)

all_rules = rules

rules_in = '''
        50-udev-default.rules
        64-btrfs.rules
        99-systemd.rules
'''.split()

foreach file : rules_in
        gen = configure_file(
                input : file + '.in',
                output : file,
                configuration : substs)
        install_data(gen,
                     install_dir : udevrulesdir)
        all_rules += gen
endforeach
