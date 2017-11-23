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

units = [
        'basic.target',
        'bluetooth.target',
        'default.target',
        'exit.target',
        'graphical-session-pre.target',
        'graphical-session.target',
        'paths.target',
        'printer.target',
        'shutdown.target',
        'smartcard.target',
        'sockets.target',
        'sound.target',
        'timers.target',
        'systemd-tmpfiles-clean.timer',
]

foreach file : units
        install_data(file,
                     install_dir : userunitdir)
endforeach

in_units = [
        'systemd-exit.service',
        'systemd-tmpfiles-clean.service',
        'systemd-tmpfiles-setup.service',
]

foreach file : in_units
        gen = configure_file(
                input : file + '.in',
                output : file,
                configuration : substs)
        install_data(gen,
                     install_dir : userunitdir)
endforeach
