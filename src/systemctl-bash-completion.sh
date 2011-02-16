# This file is part of systemd.
#
# Copyright 2010 Ran Benita
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

__contains_word () {
        local word=$1; shift
        for w in $*; do [[ $w = $word ]] && return 0; done
        return 1
}

__filter_units_by_property () {
        local property=$1 value=$2 ; shift ; shift
        local -a units=( $* )
        local -a props=( $(systemctl show --property "$property" -- ${units[*]} | grep -v ^$) )
        for ((i=0; $i < ${#units[*]}; i++)); do
                if [[ "${props[i]}" = "$property=$value" ]]; then
                        echo "${units[i]}"
                fi
        done
}

__get_all_units      () { systemctl list-units --full --all | awk '                 {print $1}' ; }
__get_active_units   () { systemctl list-units --full       | awk '                 {print $1}' ; }
__get_inactive_units () { systemctl list-units --full --all | awk '$3 == "inactive" {print $1}' ; }
__get_failed_units   () { systemctl list-units --full       | awk '$3 == "failed"   {print $1}' ; }

_systemctl () {
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local verb comps

        local -A OPTS=(
               [STANDALONE]='--all -a --defaults --fail --ignore-dependencies --failed --force -f --full --global
                             --help -h --no-ask-password --no-block --no-reload --no-wall
                             --order --require --quiet -q --system --user --version'
                      [ARG]='--kill-mode --kill-who --property -p --signal -s --type -t'
        )

        if __contains_word "$prev" ${OPTS[ARG]}; then
                case $prev in
                        --signal|-s)
                                comps=$(compgen -A signal | grep '^SIG' | grep -Ev 'RTMIN|RTMAX|JUNK')
                        ;;
                        --type|-t)
                                comps='automount device mount path service snapshot socket swap target timer'
                        ;;
                        --kill-who)
                                comps='all control main'
                        ;;
                        --kill-mode)
                                comps='control-group process process-group'
                        ;;
                        --property|-p)
                                comps=''
                        ;;
                esac
                COMPREPLY=( $(compgen -W "$comps" -- "$cur") )
                return 0
        fi


        if [[ "$cur" = -* ]]; then
                COMPREPLY=( $(compgen -W "${OPTS[*]}" -- "$cur") )
                return 0
        fi

        local -A VERBS=(
                [ALL_UNITS]='enable disable is-active is-enabled status show'
             [FAILED_UNITS]='reset-failed'
          [STARTABLE_UNITS]='start restart reload-or-restart'
          [STOPPABLE_UNITS]='stop kill try-restart condrestart'
         [ISOLATEBLE_UNITS]='isolate'
         [RELOADABLE_UNITS]='reload reload-or-try-restart force-reload'
                     [JOBS]='cancel'
                [SNAPSHOTS]='delete'
                     [ENVS]='set-environment unset-environment'
               [STANDALONE]='daemon-reexec daemon-reload default dot dump emergency exit halt kexec
                             list-jobs list-units poweroff reboot rescue show-environment'
                     [NAME]='snapshot load'
        )

        local verb
        for ((i=0; $i <= $COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]} &&
                 ! __contains_word "${COMP_WORDS[i-1]}" ${OPTS[ARG}]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if   [[ -z $verb ]]; then
                comps="${VERBS[*]}"

        elif __contains_word "$verb" ${VERBS[ALL_UNITS]}; then
                comps=$( __get_all_units )

        elif __contains_word "$verb" ${VERBS[STARTABLE_UNITS]}; then
                comps=$( __filter_units_by_property CanStart yes \
                      $( __get_inactive_units | grep -Ev '\.(device|snapshot)$' ))

        elif __contains_word "$verb" ${VERBS[STOPPABLE_UNITS]}; then
                comps=$( __filter_units_by_property CanStop yes \
                      $( __get_active_units ) )

        elif __contains_word "$verb" ${VERBS[RELOADABLE_UNITS]}; then
                comps=$( __filter_units_by_property CanReload yes \
                      $( __get_active_units ) )

        elif __contains_word "$verb" ${VERBS[ISOLATABLE_UNITS]}; then
                comps=$( __filter_units_by_property AllowIsolate yes \
                      $( __get_all_units ) )

        elif __contains_word "$verb" ${VERBS[FAILED_UNITS]}; then
                comps=$( __get_failed_units )

        elif __contains_word "$verb" ${VERBS[STANDALONE]} ${VERBS[NAME]}; then
                comps=''

        elif __contains_word "$verb" ${VERBS[JOBS]}; then
                comps=$( systemctl list-jobs | awk '{print $1}' )

        elif __contains_word "$verb" ${VERBS[SNAPSHOTS]}; then
                comps=$( systemctl list-units --type snapshot --full --all | awk '{print $1}' )

        elif __contains_word "$verb" ${VERBS[ENVS]}; then
                comps=$( systemctl show-environment | sed 's_\([^=]\+=\).*_\1_' )
                compopt -o nospace
        fi

        COMPREPLY=( $(compgen -W "$comps" -- "$cur") )
        return 0
}
complete -F _systemctl systemctl
