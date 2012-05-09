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

__systemctl() {
        systemctl --full --no-legend "$@"
}

__contains_word () {
        local word=$1; shift
        for w in $*; do [[ $w = $word ]] && return 0; done
        return 1
}

__filter_units_by_property () {
        local property=$1 value=$2 ; shift 2
        local units=("$@")
        local props
        IFS=$'\n' read -rd '' -a props < \
            <(__systemctl show --property "$property" -- "${units[@]}")
        for ((i=0; $i < ${#units[*]}; i++)); do
                if [[ "${props[i]}" = "$property=$value" ]]; then
                        printf "%s\n" "${units[i]}"
                fi
        done
}

__get_all_units      () { __systemctl list-units --all \
        | { while read -r a b; do printf "%s\n" "$a"; done; }; }
__get_active_units   () { __systemctl list-units       \
        | { while read -r a b; do printf "%s\n" "$a"; done; }; }
__get_inactive_units () { __systemctl list-units --all \
        | { while read -r a b c d; do [[ $c == "inactive" ]] && printf "%s\n" "$a"; done; }; }
__get_failed_units   () { __systemctl list-units       \
        | { while read -r a b c d; do [[ $c == "failed"   ]] && printf "%s\n" "$a"; done; }; }
__get_enabled_units  () { __systemctl list-unit-files  \
        | { while read -r a b c  ; do [[ $b == "enabled"  ]] && printf "%s\n" "$a"; done; }; }
__get_disabled_units () { __systemctl list-unit-files  \
        | { while read -r a b c  ; do [[ $b == "disabled" ]] && printf "%s\n" "$a"; done; }; }
__get_masked_units   () { __systemctl list-unit-files  \
        | { while read -r a b c  ; do [[ $b == "masked"   ]] && printf "%s\n" "$a"; done; }; }

_systemctl () {
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local verb comps

        local -A OPTS=(
               [STANDALONE]='--all -a --defaults --fail --ignore-dependencies --failed --force -f --full --global
                             --help -h --no-ask-password --no-block --no-legend --no-pager --no-reload --no-wall
                             --order --require --quiet -q --privileged -P --system --user --version --runtime'
                      [ARG]='--host -H --kill-mode --kill-who --property -p --signal -s --type -t --root'
        )

        if __contains_word "$prev" ${OPTS[ARG]}; then
                case $prev in
                        --signal|-s)
                                comps=$(compgen -A signal)
                        ;;
                        --type|-t)
                                comps='automount device mount path service snapshot socket swap target timer'
                        ;;
                        --kill-who)
                                comps='all control main'
                        ;;
                        --kill-mode)
                                comps='control-group process'
                        ;;
                        --root)
                                comps=$(compgen -A directory -- "$cur" )
                                compopt -o filenames
                        ;;
                        --host|-H)
                                comps=$(compgen -A hostname)
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

        local -A VERBS=(
                [ALL_UNITS]='is-active is-enabled status show mask preset'
            [ENABLED_UNITS]='disable reenable'
           [DISABLED_UNITS]='enable'
             [FAILED_UNITS]='reset-failed'
          [STARTABLE_UNITS]='start'
          [STOPPABLE_UNITS]='stop condstop kill try-restart condrestart'
         [ISOLATABLE_UNITS]='isolate'
         [RELOADABLE_UNITS]='reload condreload reload-or-try-restart force-reload'
        [RESTARTABLE_UNITS]='restart reload-or-restart'
             [MASKED_UNITS]='unmask'
                     [JOBS]='cancel'
                [SNAPSHOTS]='delete'
                     [ENVS]='set-environment unset-environment'
               [STANDALONE]='daemon-reexec daemon-reload default dot dump
                             emergency exit halt kexec list-jobs list-units
                             list-unit-files poweroff reboot rescue show-environment'
                     [NAME]='snapshot load'
                     [FILE]='link'
        )

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

        elif __contains_word "$verb" ${VERBS[ENABLED_UNITS]}; then
                comps=$( __get_enabled_units )

        elif __contains_word "$verb" ${VERBS[DISABLED_UNITS]}; then
                comps=$( __get_disabled_units )

        elif __contains_word "$verb" ${VERBS[STARTABLE_UNITS]}; then
                comps=$( __filter_units_by_property CanStart yes \
                      $( __get_inactive_units \
		        | while read -r line; do \
		                [[ "$line" =~ \.(device|snapshot)$ ]] || printf "%s\n" "$line"; \
		        done ))

        elif __contains_word "$verb" ${VERBS[RESTARTABLE_UNITS]}; then
                comps=$( __filter_units_by_property CanStart yes \
                      $( __get_all_units \
		        | while read -r line; do \
		                [[ "$line" =~ \.(device|snapshot|socket|timer)$ ]] || printf "%s\n" "$line"; \
		        done ))

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

        elif __contains_word "$verb" ${VERBS[MASKED_UNITS]}; then
                comps=$( __get_masked_units )

        elif __contains_word "$verb" ${VERBS[STANDALONE]} ${VERBS[NAME]}; then
                comps=''

        elif __contains_word "$verb" ${VERBS[JOBS]}; then
                comps=$( __systemctl list-jobs | { while read -r a b; do printf "%s\n" "$a"; done; } )

        elif __contains_word "$verb" ${VERBS[SNAPSHOTS]}; then
                comps=$( __systemctl list-units --type snapshot --full --all \
                        | { while read -r a b; do printf "%s\n" "$a"; done; } )

        elif __contains_word "$verb" ${VERBS[ENVS]}; then
                comps=$( __systemctl show-environment \
                    | while read -r line; do printf "%s\n" "${line%%=*}=";done )
                compopt -o nospace

        elif __contains_word "$verb" ${VERBS[FILE]}; then
                comps=$( compgen -A file -- "$cur" )
                compopt -o filenames
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}
complete -F _systemctl systemctl

__get_all_sessions () { systemd-loginctl list-sessions | { while read -r a b; do printf "%s\n" "$a"; done; } ; }
__get_all_users    () { systemd-loginctl list-users    | { while read -r a b; do printf "%s\n" "$b"; done; } ; }
__get_all_seats    () { systemd-loginctl list-seats    | { while read -r a b; do printf "%s\n" "$a"; done; } ; }

_loginctl () {
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local verb comps

        local -A OPTS=(
               [STANDALONE]='--all -a --help -h --no-pager --privileged -P --version'
                      [ARG]='--host -H --kill-who --property -p --signal -s'
        )

        if __contains_word "$prev" ${OPTS[ARG]}; then
                case $prev in
                        --signal|-s)
                                comps=$(compgen -A signal)
                        ;;
                        --kill-who)
                                comps='all leader'
                        ;;
                        --host|-H)
                                comps=$(compgen -A hostname)
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

        local -A VERBS=(
                [SESSIONS]='session-status show-session activate lock-session unlock-session terminate-session kill-session'
                [USERS]='user-status show-user enable-linger disable-linger terminate-user kill-user'
                [SEATS]='seat-status show-seat terminate-seat'
                [STANDALONE]='list-sessions list-users list-seats flush-devices'
                [ATTACH]='attach'
        )

        for ((i=0; $i <= $COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]} &&
                 ! __contains_word "${COMP_WORDS[i-1]}" ${OPTS[ARG}]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if   [[ -z $verb ]]; then
                comps="${VERBS[*]}"

        elif __contains_word "$verb" ${VERBS[SESSIONS]}; then
                comps=$( __get_all_sessions )

        elif __contains_word "$verb" ${VERBS[USERS]}; then
                comps=$( __get_all_users )

        elif __contains_word "$verb" ${VERBS[SEATS]}; then
                comps=$( __get_all_seats )

        elif __contains_word "$verb" ${VERBS[STANDALONE]}; then
                comps=''

        elif __contains_word "$verb" ${VERBS[ATTACH]}; then
                if [[ $prev = $verb ]]; then
                        comps=$( __get_all_seats )
                else
                        comps=$(compgen -A file -- "$cur" )
                        compopt -o filenames
                fi
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}
complete -F _loginctl loginctl
