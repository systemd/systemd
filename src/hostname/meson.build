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

if conf.get('ENABLE_HOSTNAMED') == 1
        install_data('org.freedesktop.hostname1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.hostname1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.hostname1.policy',
                     install_dir : polkitpolicydir)
endif
