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

zshcompletiondir = get_option('zshcompletiondir')
if zshcompletiondir == ''
        zshcompletiondir = join_paths(datadir, 'zsh/site-functions')

        message('zsh completions: @0@'.format(zshcompletiondir))
endif

if zshcompletiondir != 'no'
        zsh_systemctl = configure_file(
                input : '_systemctl.in',
                output : '_systemctl',
                configuration : substs)

        items = [['_busctl',                   ''],
                 ['_journalctl',               ''],
                 ['_systemd-analyze',          ''],
                 ['_systemd-delta',            ''],
                 ['_systemd-nspawn',           ''],
                 ['_systemd',                  ''],
                 ['_systemd-run',              ''],
                 ['_udevadm',                  ''],
                 ['_kernel-install',           ''],
                 ['_sd_hosts_or_user_at_host', ''],
                 ['_sd_outputmodes',           ''],
                 ['_sd_unit_files',            ''],
                 ['_sd_machines',              ''],
                 [zsh_systemctl,               ''],
                 ['_bootctl',                  'ENABLE_EFI'],
                 ['_coredumpctl',              'ENABLE_COREDUMP'],
                 ['_hostnamectl',              'ENABLE_HOSTNAMED'],
                 ['_localectl',                'ENABLE_LOCALED'],
                 ['_loginctl',                 'ENABLE_LOGIND'],
                 ['_machinectl',               'ENABLE_MACHINED'],
                 ['_networkctl',               'ENABLE_NETWORKD'],
                 ['_systemd-inhibit',          'ENABLE_LOGIND'],
                 ['_systemd-resolve',          'ENABLE_RESOLVE'],
                 ['_systemd-tmpfiles',         'ENABLE_TMPFILES'],
                 ['_timedatectl',              'ENABLE_TIMEDATED'],
                ]

        foreach item : items
                if item[1] == '' or conf.get(item[1]) == 1
                        install_data(item[0],
                                     install_dir : zshcompletiondir)
                endif
        endforeach
endif
