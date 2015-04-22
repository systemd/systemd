#compdef systemd-analyze

_systemd_analyze_set-log-level() {
    local -a _levels
    _levels=(debug info notice warning err crit alert emerg)
    _describe -t level 'logging level' _levels || compadd "$@"
}

_systemd_analyze_verify() {
    _sd_unit_files
}

_systemd_analyze_command(){
    local -a _systemd_analyze_cmds
    # Descriptions taken from systemd-analyze --help.
    _systemd_analyze_cmds=(
        'time:Print time spent in the kernel before reaching userspace'
        'blame:Print list of running units ordered by time to init'
        'critical-chain:Print a tree of the time critical chain of units'
        'plot:Output SVG graphic showing service initialization'
        'dot:Dump dependency graph (in dot(1) format)'
        'dump:Dump server status'
        'set-log-level:Set systemd log threshold'
        'verify:Check unit files for correctness'
    )

    if (( CURRENT == 1 )); then
        _describe "options" _systemd_analyze_cmds
    else
        local curcontext="$curcontext"
        cmd="${${_systemd_analyze_cmds[(r)$words[1]:*]%%:*}}"
        if (( $#cmd )); then
            if (( $+functions[_systemd_analyze_$cmd] )) && (( CURRENT == 2 )); then
                _systemd_analyze_$cmd
            else
                _message "no more options"
            fi
        else
            _message "unknown systemd-analyze command: $words[1]"
        fi
    fi
}

_arguments \
    {-h,--help}'[Show help text]' \
    '--version[Show package version]' \
    '--system[Operate on system systemd instance]' \
    '--user[Operate on user systemd instance]' \
    '--no-pager[Do not pipe output into a pager]' \
    '--man=[Do (not) check for existence of man pages]:boolean:(1 0)' \
    '--order[When generating graph for dot, show only order]' \
    '--require[When generating graph for dot, show only requirement]' \
    '--fuzz=[When printing the tree of the critical chain, print also services, which finished TIMESPAN earlier, than the latest in the branch]:TIMESPAN' \
    '--from-pattern=[When generating a dependency graph, filter only origins]:GLOB' \
    '--to-pattern=[When generating a dependency graph, filter only destinations]:GLOB' \
    {-H+,--host=}'[Operate on remote host]:userathost:_sd_hosts_or_user_at_host' \
    {-M+,--machine=}'[Operate on local container]:machine:_sd_machines' \
    '*::systemd-analyze commands:_systemd_analyze_command'
