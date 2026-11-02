# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash

# The completion function of each program declares the tables options, verbs, opts, choices,
# verb_choices, verb_arguments, and verb_max as local variables and then calls this function. Bash
# uses dynamic scoping, so this function reads the tables of its caller.
# shellcheck disable=SC2154
__systemd_complete() {
    # _comp_initialize sets prev. shellcheck warns about prev because this function never reads it.
    # shellcheck disable=SC2034
    local cur prev words cword wordbreak_prefix word option="" verb="" prefix="" kind="" name candidate rest
    local -i i j position=0 continue_options=1

    # Bash splits the command line into separate words at "=" and ":". _comp_initialize -n =: joins
    # the parts again, so KEY:@PATH ends up in a single word.
    # bash-completion turns off hostcomplete, which removes "@" from the word breaks.
    _comp_initialize -n =: || return

    # Readline replaces only the part of the word after the last separator, which is $2. The
    # replies must not contain the part before it.
    wordbreak_prefix=${cur%"$2"}

    for ((i = 1; i <= cword; i++)); do
        word=${words[i]}
        if [[ -n $option ]]; then
            if ((i == cword)); then
                cur=$word
                break
            fi
            option=""
        elif ((continue_options)) && [[ $word == -- ]] && ((i < cword)); then
            continue_options=0
        elif ((continue_options)) && [[ $word == --* ]]; then
            name=${word%%=*}
            candidate=$name
            if [[ -z ${opts[$name]+x} ]]; then
                # The option parser accepts a unique prefix of a long option.
                candidate=""
                for rest in "${!opts[@]}"; do
                    [[ $rest == --* && $rest == "$name"* ]] || continue
                    if [[ -n $candidate ]]; then
                        candidate=""
                        break
                    fi
                    candidate=$rest
                done
            fi
            if [[ -n $candidate && -n ${opts[$candidate]} ]]; then
                if [[ $word == *=* ]]; then
                    if ((i == cword)); then
                        option=$candidate
                        prefix=${name}=
                        cur=${word#*=}
                        break
                    fi
                elif [[ ${opts[$candidate]} != \?* ]] && ((i < cword)); then
                    option=$candidate
                    continue
                fi
            fi
            if ((i == cword)); then
                _comp_compgen_split -- "${options[*]}"
                return
            fi
        elif ((continue_options)) && [[ $word == -* ]]; then
            for ((j = 1; j < ${#word}; j++)); do
                name=-${word:j:1}
                [[ -n ${opts[$name]-} ]] || continue
                if ((j + 1 < ${#word})); then
                    if ((i == cword)); then
                        option=$name
                        prefix=${word:0:j+1}
                        cur=${word:j+1}
                    fi
                elif [[ ${opts[$name]} != \?* ]] && ((i < cword)); then
                    option=$name
                fi
                break
            done
            if ((i == cword)) && [[ -z $option ]]; then
                _comp_compgen_split -- "${options[*]}"
                return
            fi
        elif ((i < cword)); then
            [[ -n $verb ]] || verb=$word
            position=$((position + 1))
        fi
    done

    if [[ -n $option ]]; then
        kind=${opts[$option]#\?}
        if [[ -n ${choices[$option]-} ]]; then
            _comp_compgen_split -- "${choices[$option]}"
            kind=""
        fi
    elif [[ -z $verb ]]; then
        _comp_compgen_split -- "${verbs[*]}"
    elif [[ -z ${verb_max[$verb]-} ]] || ((position < verb_max[$verb])); then
        if [[ -n ${verb_choices[$verb]-} ]]; then
            _comp_compgen_split -- "${verb_choices[$verb]}"
        else
            kind=${verb_arguments[$verb]-}
        fi
    fi

    if [[ $kind == at-file || $kind == key-at-file ]]; then
        # Undo Readline's quoting of @ when continuing a previously completed path.
        cur=${cur/\\@/@}
    fi
    if [[ $kind == key-at-file ]]; then
        [[ $cur == *:* ]] || return
        prefix+=${cur%%:*}:
        cur=${cur#*:}
        [[ $cur == *@* ]] || return
        prefix+=${cur%%@*}
        cur=@${cur#*@}
        kind=at-file
    fi
    if [[ $kind == at-file ]]; then
        [[ $cur == @* ]] || return
        prefix+=@
        cur=${cur#@}
        kind='file'
    fi

    if [[ $kind == file ]]; then
        _comp_compgen_filedir
    elif [[ $kind == directory ]]; then
        _comp_compgen_filedir -d
    fi

    for i in "${!COMPREPLY[@]}"; do
        word="${COMPREPLY[i]}"
        # The replies contain a prefix, so Readline can't tell that a reply is a directory.
        if [[ ( $kind == file || $kind == directory ) && -d $word ]]; then
            word+=/
            compopt -o nospace
        fi
        word="${prefix}${word}"
        COMPREPLY[i]=${word#"$wordbreak_prefix"}
    done
}
