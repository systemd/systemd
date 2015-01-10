# localectl(1) completion                                 -*- shell-script -*-
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

__locale_fields=( LANG LANGUAGE LC_CTYPE LC_NUMERIC LC_TIME \
                  LC_COLLATE LC_MONETARY LC_MESSAGES LC_PAPER \
                  LC_NAME LC_ADDRESS LC_TELEPHONE \
                  LC_MEASUREMENT LC_IDENTIFICATION )
# LC_ALL is omitted on purpose

_localectl() {
        local i verb comps locale_vals
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local OPTS='-h --help --version --no-convert --no-pager --no-ask-password
                    -H --host --machine'

        if __contains_word "$prev" $OPTS; then
                case $prev in
                        --host|-H)
                                comps=''
                        ;;
                esac
                COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
                return 0
        fi

        if [[ $cur = -* ]]; then
                COMPREPLY=( $(compgen -W '${OPTS[*]}' -- "$cur") )
                return 0
        fi

        local -A VERBS=(
               [STANDALONE]='status list-locales list-keymaps'
                  [LOCALES]='set-locale'
                  [KEYMAPS]='set-keymap'
                      [X11]='set-x11-keymap'
        )

        for ((i=0; i < COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if [[ -z $verb ]]; then
                comps=${VERBS[*]}
        elif __contains_word "$verb" ${VERBS[LOCALES]}; then
                if [[ $cur = *=* ]]; then
                        mapfile -t locale_vals < <(command localectl list-locales 2>/dev/null)
                        COMPREPLY=( $(compgen -W '${locale_vals[*]}' -- "${cur#=}") )
                elif [[ $prev = "=" ]]; then
                        mapfile -t locale_vals < <(command localectl list-locales 2>/dev/null)
                        COMPREPLY=( $(compgen -W '${locale_vals[*]}' -- "$cur") )
                else
                        compopt -o nospace
                        COMPREPLY=( $(compgen -W '${__locale_fields[*]}' -S= -- "$cur") )
                fi
                return 0
        elif __contains_word "$verb" ${VERBS[KEYMAPS]}; then
                comps=$(command localectl list-keymaps)
        elif __contains_word "$verb" ${VERBS[STANDALONE]} ${VERBS[X11]}; then
                comps=''
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}

complete -F _localectl localectl
