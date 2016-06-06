# machinectl(1) completion                      -*- shell-script -*-
#
# This file is part of systemd.
#
# Copyright 2014 Thomas H.P. Andersen
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

__contains_word() {
        local w word=$1; shift
        for w in "$@"; do
                [[ $w = "$word" ]] && return
        done
}

__get_machines() {
        local a b
        (machinectl list-images --no-legend --no-pager; machinectl list --no-legend --no-pager; echo ".host") | \
		{ while read a b; do echo " $a"; done; } | sort -u;
}

_machinectl() {
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local i verb comps

        local -A OPTS=(
               [STANDALONE]='--all -a --full --help -h --no-ask-password --no-legend --no-pager --version'
                      [ARG]='--host -H --kill-who -M --machine --property -p --signal -s'
        )

        local -A VERBS=(
               [STANDALONE]='list list-images pull-tar pull-raw import-tar import-raw export-tar export-raw list-transfers cancel-transfer'
                 [MACHINES]='status show start stop login shell enable disable poweroff reboot terminate kill copy-to copy-from image-status show-image clone rename read-only remove set-limit'
        )

        _init_completion || return

        for ((i=0; i <= COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]} &&
                 ! __contains_word "${COMP_WORDS[i-1]}" ${OPTS[ARG]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if __contains_word "$prev" ${OPTS[ARG]}; then
                case $prev in
                        --signal|-s)
                                _signals
                                return
                        ;;
                        --kill-who)
                                comps='all leader'
                        ;;
                        --host|-H)
                                comps=$(compgen -A hostname)
                        ;;
                        --machine|-M)
                                comps=$( __get_machines )
                        ;;
                        --property|-p)
                                comps=''
                        ;;
                esac
                COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
                return 0
        fi

        if [[ "$cur" = -* ]]; then
                COMPREPLY=( $(compgen -W '${OPTS[*]}' -- "$cur") )
                return 0
        fi

        if [[ -z $verb ]]; then
                comps=${VERBS[*]}

        elif __contains_word "$verb" ${VERBS[STANDALONE]}; then
                comps=''

        elif __contains_word "$verb" ${VERBS[MACHINES]}; then
                comps=$( __get_machines )
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}

complete -F _machinectl machinectl
