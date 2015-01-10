# systemd-analyze(1) completion                      -*- shell-script -*-
#
# This file is part of systemd.
#
# Copyright 2010 Ran Benita
# Copyright 2013 Harald Hoyer
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

__get_machines() {
        local a b
        machinectl list --no-legend --no-pager | { while read a b; do echo " $a"; done; };
}

_systemd_analyze() {
        local i verb comps
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}

        local -A OPTS=(
               [STANDALONE]='--help --version --system --user --from-pattern --to-pattern --order --require --no-pager'
                      [ARG]='-H --host -M --machine --fuzz --man'
        )

        local -A VERBS=(
                [STANDALONE]='time blame plot dump'
                [CRITICAL_CHAIN]='critical-chain'
                [DOT]='dot'
                [LOG_LEVEL]='set-log-level'
                [VERIFY]='verify'
        )

        _init_completion || return

        for ((i=0; i < COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]} &&
                 ! __contains_word "${COMP_WORDS[i-1]}" ${OPTS[ARG]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if __contains_word "$prev" ${OPTS[ARG]}; then
                case $prev in
                        --host|-H)
                                comps=$(compgen -A hostname)
                        ;;
                        --machine|-M)
                                comps=$( __get_machines )
                        ;;
                esac
                COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
                return 0
        fi

        if [[ -z $verb  && $cur = -* ]]; then
                COMPREPLY=( $(compgen -W '${OPTS[*]}' -- "$cur") )
                return 0
        fi

        if [[ -z $verb ]]; then
                comps=${VERBS[*]}

        elif __contains_word "$verb" ${VERBS[STANDALONE]}; then
                if [[ $cur = -* ]]; then
                        comps='--help --version --system --user'
                fi

        elif __contains_word "$verb" ${VERBS[CRITICAL_CHAIN]}; then
                if [[ $cur = -* ]]; then
                        comps='--help --version --system --user --fuzz'
                fi

        elif __contains_word "$verb" ${VERBS[DOT]}; then
                if [[ $cur = -* ]]; then
                        comps='--help --version --system --user --from-pattern --to-pattern --order --require'
                fi

        elif __contains_word "$verb" ${VERBS[LOG_LEVEL]}; then
                if [[ $cur = -* ]]; then
                        comps='--help --version --system --user'
                else
                        comps='debug info notice warning err crit alert emerg'
                fi

        elif __contains_word "$verb" ${VERBS[VERIFY]}; then
                if [[ $cur = -* ]]; then
                        comps='--help --version --system --user --no-man'
                else
                        comps=$( compgen -A file -- "$cur" )
                        compopt -o filenames
                fi

        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}

complete -F _systemd_analyze systemd-analyze
