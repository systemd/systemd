# hostnamectl(1) completion                               -*- shell-script -*-
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

_hostnamectl() {
        local i verb comps
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local OPTS='-h --help --version --transient --static --pretty
                    --no-ask-password -H --host --machine'

        if [[ $cur = -* ]]; then
                COMPREPLY=( $(compgen -W '${OPTS[*]}' -- "$cur") )
                return 0
        fi

        local -A VERBS=(
                [STANDALONE]='status'
                     [ICONS]='set-icon-name'
                      [NAME]='set-hostname set-deployment set-location'
                   [CHASSIS]='set-chassis'
        )

        for ((i=0; i < COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if [[ -z $verb ]]; then
                comps=${VERBS[*]}
        elif __contains_word "$verb" ${VERBS[CHASSIS]}; then
                comps='desktop laptop server tablet handset watch embedded vm container'
        elif __contains_word "$verb" ${VERBS[STANDALONE]} ${VERBS[ICONS]} ${VERBS[NAME]}; then
                comps=''
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}

complete -F _hostnamectl hostnamectl
