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

bashcompletiondir = get_option('bashcompletiondir')
if bashcompletiondir == ''
        bash_completion = dependency('bash-completion', required : false)
        if bash_completion.found()
                bashcompletiondir = bash_completion.get_pkgconfig_variable('completionsdir')
        else
                bashcompletiondir = join_paths(datadir, 'bash-completion/completions')
        endif

        message('bash completions: @0@'.format(bashcompletiondir))
endif

if bashcompletiondir != 'no'
        bash_systemctl = configure_file(
                input : 'systemctl.in',
                output : 'systemctl',
                configuration : substs)

        items = [['busctl',              ''],
                 ['journalctl',          ''],
                 ['systemd-analyze',     ''],
                 ['systemd-cat',         ''],
                 ['systemd-cgls',        ''],
                 ['systemd-cgtop',       ''],
                 ['systemd-delta',       ''],
                 ['systemd-detect-virt', ''],
                 ['systemd-nspawn',      ''],
                 ['systemd-path',        ''],
                 ['systemd-run',         ''],
                 ['udevadm',             ''],
                 ['kernel-install',      ''],
                 [bash_systemctl,        ''],
                 ['bootctl',             'ENABLE_EFI'],
                 ['coredumpctl',         'ENABLE_COREDUMP'],
                 ['hostnamectl',         'ENABLE_HOSTNAMED'],
                 ['localectl',           'ENABLE_LOCALED'],
                 ['loginctl',            'ENABLE_LOGIND'],
                 ['machinectl',          'ENABLE_MACHINED'],
                 ['networkctl',          'ENABLE_NETWORKD'],
                 ['systemd-resolve',     'ENABLE_RESOLVE'],
                 ['timedatectl',         'ENABLE_TIMEDATED'],
                ]

        foreach item : items
                if item[1] == '' or conf.get(item[1]) == 1
                        install_data(item[0],
                                     install_dir : bashcompletiondir)
                endif
        endforeach
endif
