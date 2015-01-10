# journalctl(1) completion                                -*- shell-script -*-
#
# This file is part of systemd.
#
# Copyright 2010 Ran Benita
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

__contains_word () {
        local w word=$1; shift
        for w in "$@"; do
                [[ $w = "$word" ]] && return
        done
}

__journal_fields=(MESSAGE{,_ID} PRIORITY CODE_{FILE,LINE,FUNC}
                  ERRNO SYSLOG_{FACILITY,IDENTIFIER,PID} COREDUMP_EXE
                  _{P,U,G}ID _COMM _EXE _CMDLINE
                  _AUDIT_{SESSION,LOGINUID}
                  _SYSTEMD_{CGROUP,SESSION,UNIT,OWNER_UID}
                  _SELINUX_CONTEXT _SOURCE_REALTIME_TIMESTAMP
                  _{BOOT,MACHINE}_ID _HOSTNAME _TRANSPORT
                  _KERNEL_{DEVICE,SUBSYSTEM}
                  _UDEV_{SYSNAME,DEVNODE,DEVLINK}
                  __CURSOR __{REALTIME,MONOTONIC}_TIMESTAMP)

__syslog_priorities=(emerg alert crit err warning notice info debug)

_journalctl() {
        local field_vals= cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local -A OPTS=(
                [STANDALONE]='-a --all --full --system --user
                              --disk-usage -f --follow --header
                              -h --help -l --local --new-id128 -m --merge --no-pager
                              --no-tail -q --quiet --setup-keys --this-boot --verify
                              --version --list-catalog --update-catalog --list-boots
                              --show-cursor --dmesg -k --pager-end -e -r --reverse
                              --utc -x --catalog --no-full --force --dump-catalog
                              --flush'
                       [ARG]='-b --boot --this-boot -D --directory --file -F --field
                              -o --output -u --unit --user-unit -p --priority'
                [ARGUNKNOWN]='-c --cursor --interval -n --lines --since --until
                              --after-cursor --verify-key --identifier
                              --root --machine'
        )

        if __contains_word "$prev" ${OPTS[ARG]} ${OPTS[ARGUNKNOWN]}; then
                case $prev in
                        --boot|--this-boot|-b)
                                comps=$(journalctl -F '_BOOT_ID' 2>/dev/null)
                        ;;
                        --directory|-D)
                                comps=$(compgen -d -- "$cur")
                                compopt -o filenames
                        ;;
                        --file)
                                comps=$(compgen -f -- "$cur")
                                compopt -o filenames
                        ;;
                        --output|-o)
                                comps='short short-iso short-precise short-monotonic verbose export json json-pretty json-sse cat'
                        ;;
                        --field|-F)
                                comps=${__journal_fields[*]}
                        ;;
                        --priority|-p)
                                comps=${__syslog_priorities[*]}
                        ;;
                        --unit|-u)
                                comps=$(journalctl -F '_SYSTEMD_UNIT' 2>/dev/null)
                        ;;
                        --user-unit)
                                comps=$(journalctl -F '_SYSTEMD_USER_UNIT' 2>/dev/null)
                        ;;
                        *)
                                return 0
                        ;;
                esac
                COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
                return 0
        fi

        if [[ $cur = -* ]]; then
                COMPREPLY=( $(compgen -W '${OPTS[*]}' -- "$cur") )
                return 0
        elif [[ $cur = *=* ]]; then
                mapfile -t field_vals < <(journalctl -F "${prev%=}" 2>/dev/null)
                COMPREPLY=( $(compgen -W '${field_vals[*]}' -- "${cur#=}") )
        elif [[ $cur = /dev* ]]; then
                compopt -o filenames
                COMPREPLY=( $(compgen -f -- "${cur}") )
        elif [[ $cur = /* ]]; then
                # Append /dev/ to the list of completions, so that
                # after typing /<TAB><TAB> the user sees /dev/ as one
                # of the alternatives. Later on the rule above will
                # take care of showing device files in /dev/.
                mapfile -t field_vals < <(journalctl -F "_EXE" 2>/dev/null; echo '/dev/')
                COMPREPLY=( $(compgen -W '${field_vals[*]}' -- "${cur}") )
                if [[ "${COMPREPLY[@]}" = '/dev/' ]]; then
                    compopt -o filenames
                    COMPREPLY=( $(compgen -f -- "${cur}") )
                fi
        elif [[ $prev = '=' ]]; then
                mapfile -t field_vals < <(journalctl -F "${COMP_WORDS[COMP_CWORD-2]}" 2>/dev/null)
                COMPREPLY=( $(compgen -W '${field_vals[*]}' -- "$cur") )
        else
                compopt -o nospace
                COMPREPLY=( $(compgen -W '${__journal_fields[*]}' -S= -- "$cur") )
        fi
}

complete -F _journalctl journalctl
