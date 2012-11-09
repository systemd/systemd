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
        local i verb comps

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
                 ! __contains_word "${COMP_WORDS[i-1]}" ${OPTS[ARG]}; then
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

__get_all_sessions () { loginctl list-sessions | { while read -r a b; do printf "%s\n" "$a"; done; } ; }
__get_all_users    () { loginctl list-users    | { while read -r a b; do printf "%s\n" "$b"; done; } ; }
__get_all_seats    () { loginctl list-seats    | { while read -r a b; do printf "%s\n" "$a"; done; } ; }

_loginctl () {
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local i verb comps

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
                 ! __contains_word "${COMP_WORDS[i-1]}" ${OPTS[ARG]}; then
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

_journalctl() {
        local field_vals= cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local -A OPTS=(
                [STANDALONE]='-a --all -b --this-boot --disk-usage -f --follow --header
                              -h --help -l --local --new-id128 -m --merge --no-pager
                              --no-tail -q --quiet --setup-keys --this-boot --verify
                              --version'
                       [ARG]='-D --directory -F --field -o --output -u --unit'
                [ARGUNKNOWN]='-c --cursor --interval -n --lines -p --priority --since --until
                              --verify-key'
        )

        if __contains_word "$prev" ${OPTS[ARG]} ${OPTS[ARGUNKNOWN]}; then
                case $prev in
                        --directory|-D)
                                comps=$(compgen -d -- "$cur")
                                compopt -o filenames
                        ;;
                        --output|-o)
                                comps='short short-monotonic verbose export json cat'
                        ;;
                        --field|-F)
                                comps=${__journal_fields[*]}
                        ;;
                        --unit|-u)
                                comps=$(journalctl -F '_SYSTEMD_UNIT')
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
        elif [[ $prev = '=' ]]; then
                mapfile -t field_vals < <(journalctl -F "${COMP_WORDS[COMP_CWORD-2]}" 2>/dev/null)
                COMPREPLY=( $(compgen -W '${field_vals[*]}' -- "$cur") )
        else
                compopt -o nospace
                COMPREPLY=( $(compgen -W '${__journal_fields[*]}' -S= -- "$cur") )
        fi
}
complete -F _journalctl journalctl

_coredumpctl() {
        local i verb comps
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local OPTS='-h --help --version --no-pager --no-legend -o --output -F --field'

        local -A VERBS=(
            [LIST]='list'
            [DUMP]='dump gdb'
        )

        if __contains_word "$prev" '--output -o'; then
                comps=$( compgen -A file -- "$cur" )
                compopt -o filenames
        elif __contains_word "$prev" '--FIELD -F'; then
                comps=$( compgen -W '${__journal_fields[*]}' -- "$cur" )
        elif [[ $cur = -* ]]; then
                comps=${OPTS}
        elif __contains_word "$prev" ${VERBS[*]} &&
           ! __contains_word ${COMP_WORDS[COMP_CWORD-2]} '--output -o -F --field'; then
                compopt -o nospace
                COMPREPLY=( $(compgen -W '${__journal_fields[*]}' -S= -- "$cur") )
               return 0
        elif [[ $cur = *=* ]]; then
                mapfile -t field_vals < <(systemd-coredumpctl -F "${prev%=}" 2>/dev/null)
                COMPREPLY=( $(compgen -W '${field_vals[*]}' -- "${cur#=}") )
                return 0
        elif [[ $prev = '=' ]]; then
                mapfile -t field_vals < <(systemd-coredumpctl -F "${COMP_WORDS[COMP_CWORD-2]}" 2>/dev/null)
                comps=${field_vals[*]}
        else
                for ((i=0; i <= COMP_CWORD; i++)); do
                        if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]}; then
                                verb=${COMP_WORDS[i]}
                                break
                        fi
                done

                if [[ -z $verb ]]; then
                        comps=${VERBS[*]}
                elif __contains_word "$verb" ${VERBS[LIST]} ${VERBS[DUMP]}; then
                        comps=''
                fi
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}
complete -F _coredumpctl systemd-coredumpctl

_timedatectl() {
        local i verb comps
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local OPTS='-h --help --version --adjust-system-clock --no-pager
                    --no-ask-password -H --host'

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
                  [BOOLEAN]='set-local-rtc set-ntp'
               [STANDALONE]='status set-time list-timezones'
                [TIMEZONES]='set-timezone'
                     [TIME]='set-time'
        )

        for ((i=0; i <= COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if [[ -z $verb ]]; then
                comps=${VERBS[*]}
        elif __contains_word "$verb" ${VERBS[BOOLEAN]}; then
                comps='true false'
        elif __contains_word "$verb" ${VERBS[TIMEZONES]}; then
                comps=$(command timedatectl list-timezones)
        elif __contains_word "$verb" ${VERBS[STANDALONE]} ${VERBS[TIME]}; then
                comps=''
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}
complete -F _timedatectl timedatectl

_localectl() {
        local i verb comps
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local OPTS='-h --help --version --no-convert --no-pager --no-ask-password
                    -H --host'

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

        for ((i=0; i <= COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if [[ -z $verb ]]; then
                comps=${VERBS[*]}
        elif __contains_word "$verb" ${VERBS[LOCALES]}; then
                comps=$(command localectl list-locales)
        elif __contains_word "$verb" ${VERBS[KEYMAPS]}; then
                comps=$(command localectl list-keymaps)
        elif __contains_word "$verb" ${VERBS[STANDALONE]} ${VERBS[X11]}; then
                comps=''
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}
complete -F _localectl localectl

_hostnamectl() {
        local i verb comps
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local OPTS='-h --help --version --transient --static --pretty
                    --no-ask-password -H --host'

        if [[ $cur = -* ]]; then
                COMPREPLY=( $(compgen -W '${OPTS[*]}' -- "$cur") )
                return 0
        fi

        local -A VERBS=(
                [STANDALONE]='status'
                     [ICONS]='set-icon-name'
                      [NAME]='set-hostname'
        )

        for ((i=0; i <= COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if [[ -z $verb ]]; then
                comps=${VERBS[*]}
        elif __contains_word "$verb" ${VERBS[STANDALONE]} ${VERBS[ICONS]} ${VERBS[NAME]}; then
                comps=''
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}
complete -F _hostnamectl hostnamectl

__get_all_sysdevs() {
        local -a devs=(/sys/bus/*/devices/*/ /sys/class/*/*/)
        printf '%s\n' "${devs[@]%/}"
}

_udevadm() {
        local i verb comps
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local OPTS='-h --help --version --debug'

        local -A VERBS=(
                [INFO]='info'
                [TRIGGER]='trigger'
                [SETTLE]='settle'
                [CONTROL]='control'
                [MONITOR]='monitor'
                [HWDB]='hwdb'
                [TESTBUILTIN]='test-builtin'
                [TEST]='test'
        )

        for ((i=0; $i <= $COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]} &&
                 ! __contains_word "${COMP_WORDS[i-1]}" ${OPTS[ARG]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if [[ -z $verb  && $cur = -* ]]; then
                COMPREPLY=( $(compgen -W '${OPTS[*]}' -- "$cur") )
                return 0
        fi

        if [[ -z $verb ]]; then
                comps=${VERBS[*]}

        elif __contains_word "$verb" ${VERBS[INFO]}; then
                if [[ $cur = -* ]]; then
                        comps='--help --query= --path= --name= --root --attribute-walk --export-db --cleanup-db'
                else
                        comps=$( __get_all_sysdevs )
                fi

        elif __contains_word "$verb" ${VERBS[TRIGGER]}; then
                comps='--help --verbose --dry-run --type= --action= --subsystem-match=
                       --subsystem-nomatch= --attr-match= --attr-nomatch= --property-match=
                       --tag-match= --sysname-match= --parent-match='

        elif __contains_word "$verb" ${VERBS[SETTLE]}; then
                comps='--help --timeout= --seq-start= --seq-end= --exit-if-exists= --quiet'

        elif __contains_word "$verb" ${VERBS[CONTROL]}; then
                comps='--help --exit --log-priority= --stop-exec-queue --start-exec-queue
                       --reload --property= --children-max= --timeout='

        elif __contains_word "$verb" ${VERBS[MONITOR]}; then
                comps='--help --kernel --udev --property --subsystem-match= --tag-match='

        elif __contains_word "$verb" ${VERBS[HWDB]}; then
                comps='--help --update --test='

        elif __contains_word "$verb" ${VERBS[TEST]}; then
                if [[ $cur = -* ]]; then
                        comps='--help --action='
                else
                        comps=$( __get_all_sysdevs )
                fi

        elif __contains_word "$verb" ${VERBS[TESTBUILTIN]}; then
                      comps='blkid btrfs firmware hwdb input_id kmod path_id usb_id uaccess'
        fi

        COMPREPLY=( $(compgen -W '$comps' -- "$cur") )
        return 0
}
complete -F _udevadm udevadm
