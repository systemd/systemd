#compdef coredumpctl

_coredumpctl_command(){
    local -a _coredumpctl_cmds
    _coredumpctl_cmds=(
            'list:List available coredumps'
            'info:Show detailed information about one or more coredumps'
            'dump:Print coredump to stdout'
            'gdb:Start gdb on a coredump'
    )
    if (( CURRENT == 1 )); then
        _describe -t commands 'coredumpctl command' _coredumpctl_cmds
    else
        local curcontext="$curcontext"
        local -a _dumps
        cmd="${${_coredumpctl_cmds[(r)$words[1]:*]%%:*}}"
        if (( $#cmd  )); then
            # user can set zstyle ':completion:*:*:coredumpctl:*' sort no for coredumps to be ordered by date, otherwise they get ordered by pid
            _dumps=( "${(foa)$(coredumpctl list --no-legend | awk 'BEGIN{OFS=":"} {sub(/[[ \t]+/, ""); print $5,$0}' 2>/dev/null)}" )
            if [[ -n "$_dumps" ]]; then
                _describe -t pids 'coredumps' _dumps
            else
                _message "no coredumps"
            fi
        else
            _message "no more options"
        fi
    fi
}

_arguments \
    {-o+,--output=}'[Write output to FILE]:output file:_files' \
    {-F+,--field=}'[Show field in list output]:field' \
    '-1[Show information about most recent entry only]' \
    '--no-pager[Do not pipe output into a pager]' \
    '--no-legend[Do not print the column headers]' \
    {-h,--help}'[Show this help]' \
    '--version[Show package version]' \
    '*::coredumpctl commands:_coredumpctl_command'
