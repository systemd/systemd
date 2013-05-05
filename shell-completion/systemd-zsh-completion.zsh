#compdef systemctl loginctl journalctl hostnamectl localectl timedatectl systemd-coredumpctl udevadm systemd-analyze systemd-cat systemd-ask-password systemd-cgls systemd-cgtop systemd-delta systemd-detect-virt systemd-inhibit systemd-machine-id-setup systemd-notify systemd-nspawn systemd-tmpfiles systemd-tty-ask-password-agent

_ctls()
{
    local curcontext="$curcontext" state lstate line
    case "$service" in
        systemctl)
            # -s for aggregated options like -aP
            _arguments -s \
                {-h,--help}'[Show help]' \
                '--version[Show package version]' \
                {-t,--type=}'[List only units of a particular type]:unit type:(automount device mount path service snapshot socket swap target timer)' \
                \*{-p,--property=}'[Show only properties by specific name]:unit property' \
                {-a,--all}'[Show all units/properties, including dead/empty ones]' \
                '--reverse[Show reverse dependencies]' \
                '--after[Show units ordered after]' \
                '--before[Show units ordered before]' \
                '--failed[Show only failed units]' \
                "--full[Don't ellipsize unit names on output]" \
                '--fail[When queueing a new job, fail if conflicting jobs are pending]' \
                '--ignore-dependencies[When queueing a new job, ignore all its dependencies]' \
                '--kill-who=[Who to send signal to]:killwho:(main control all)' \
                {-s,--signal=}'[Which signal to send]:signal:_signals' \
                {-H,--host=}'[Show information for remote host]:userathost:_hosts_or_user_at_host' \
                {-P,--privileged}'[Acquire privileges before execution]' \
                {-q,--quiet}'[Suppress output]' \
                '--no-block[Do not wait until operation finished]' \
                "--no-wall[Don't send wall message before halt/power-off/reboot]" \
                "--no-reload[When enabling/disabling unit files, don't reload daemon configuration]" \
                '--no-legend[Do not print a legend, i.e. the column headers and the footer with hints]' \
                '--no-pager[Do not pipe output into a pager]' \
                '--no-ask-password[Do not ask for system passwords]' \
                '--system[Connect to system manager]' \
                '--user[Connect to user service manager]' \
                '--global[Enable/disable unit files globally]' \
                {-f,--force}'[When enabling unit files, override existing symlinks. When shutting down, execute action immediately]' \
                '--root=[Enable unit files in the specified root directory]:directory:_directories' \
                '--runtime[Enable unit files only temporarily until next reboot]' \
                {-n,--lines=}'[Journal entries to show]:number of entries' \
                {-o,--output=}'[Change journal output mode]:modes:_outputmodes' \
                '*::systemctl command:_systemctl_command'
        ;;
        loginctl)
            _arguments -s \
                {-h,--help}'[Show help]' \
                '--version[Show package version]' \
                \*{-p,--property=}'[Show only properties by this name]:unit property' \
                {-a,--all}'[Show all properties, including empty ones]' \
                '--kill-who=[Who to send signal to]:killwho:(main control all)' \
                {-s,--signal=}'[Which signal to send]:signal:_signals' \
                '--no-ask-password[Do not ask for system passwords]' \
                {-H,--host=}'[Show information for remote host]:userathost:_hosts_or_user_at_host' \
                {-P,--privileged}'[Acquire privileges before execution]' \
                '--no-pager[Do not pipe output into a pager]' \
                '*::loginctl command:_loginctl_command'
        ;;

        hostnamectl)
            _arguments -s \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                '--transient[Only set transient hostname]' \
                '--static[Only set static hostname]' \
                '--pretty[Only set pretty hostname]' \
                '--no-ask-password[Do not prompt for password]' \
                {-H,--host=}'[Operate on remote host]:userathost:_hosts_or_user_at_host' \
                '*::hostnamectl commands:_hostnamectl_command'
        ;;
        journalctl)
            _arguments -s \
                '--since=[Start showing entries newer or of the specified date]:YYYY-MM-DD HH\:MM\:SS' \
                '--until=[Stop showing entries older or of the specified date]:YYYY-MM-DD HH\:MM\:SS' \
                {-c,--cursor=}'[Start showing entries from specified cursor]:cursors:_journal_fields __CURSORS' \
                {-b,--this-boot}'[Show data only from current boot]' \
                {-u,--unit=}'[Show data only from the specified unit]:units:_journal_fields _SYSTEMD_UNIT' \
                '--user-unit[Show data only from the specified user session unit]:units:_journal_fields _SYSTEMD_USER_UNIT' \
                {-p,--priority=}'[Show only messages within the specified priority range]:priority:_journal_fields PRIORITY' \
                {-f,--follow}'[Follow journal]' \
                {-n,--lines=}'[Number of journal entries to show]:integer' \
                '--no-tail[Show all lines, even in follow mode]' \
                {-o,--output=}'[Change journal output mode]:output modes:_outputmodes' \
                '--full[Show long fields in full]' \
                {-a,--all}'[Show all fields, including long and unprintable]' \
                {-q,--quiet}"[Don't show privilege warning]" \
                '--no-pager[Do not pipe output into a pager]' \
                {-m,--merge}'[Show entries from all available journals]' \
                {-D,--directory=}'[Show journal files from directory]:directories:_directories' \
                '--interval=[Time interval for changing the FSS sealing key]:time interval' \
                '--verify-key=[Specify FSS verification key]:FSS key' \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                '--new-id128[Generate a new 128 Bit ID]' \
                '--header[Show journal header information]' \
                '--disk-usage[Show total disk usage]' \
                {-F,--field=}'[List all values a certain field takes]:Fields:_list_fields' \
                '--setup-keys[Generate new FSS key pair]' \
                '--verify[Verify journal file consistency]' \
                '--list-catalog[List messages in catalog]' \
                '--update-catalog[Update binary catalog database]' \
                '*::default: _journal_none'
        ;;
        localectl)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                "--no-convert[Don't convert keyboard mappings]" \
                '--no-pager[Do not pipe output into a pager]' \
                '--no-ask-password[Do not prompt for password]' \
                {-H,--host=}'[Operate on remote host]:userathost:_hosts_or_user_at_host' \
                '*::localectl commands:_localectl_command'
        ;;
        systemd-coredumpctl)
            _arguments \
                {-o,--output=}'[Write output to FILE]:output file:_files' \
                '--no-pager[Do not pipe output into a pager]' \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                '*::systemd-coredumpctl commands:_systemd-coredumpctl_command'

        ;;
        timedatectl)
            _arguments -s \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                '--adjust-system-clock[Adjust system clock when changing local RTC mode]' \
                '--no-pager[Do not pipe output into a pager]' \
                '--no-ask-password[Do not prompt for password]' \
                {-H,--host=}'[Operate on remote host]:userathost:_hosts_or_user_at_host' \
                '*::timedatectl commands:_timedatectl_command'
        ;;
        udevadm)
            _arguments \
                '--debug[Print debug messages to stderr]' \
                '--version[Print version number]' \
                '--help[Print help text]' \
                '*::udevadm commands:_udevadm_command'
        ;;
        systemd-analyze)
            _arguments \
                {-h,--help}'[Show help text.]' \
                '--user[Shows performance data of user sessions instead of the system manager.]' \
                '--order[When generating graph for dot, show only order]' \
                '--require[When generating graph for dot, show only requirement]' \
                '*::systemd-analyze commands:_systemd_analyze_command'
        ;;
        systemd-ask-password)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--icon=[Icon name]' \
                '--timeout=[Timeout in sec]' \
                '--no-tty[Ask question via agent even on TTY]' \
                '--accept-cached[Accept cached passwords]' \
                '--multiple[List multiple passwords if available]'
        ;;
        systemd-cat)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--version[Show package version.]' \
                {-t,--identifier=}'[Set syslog identifier.]' \
                {-p,--priority=}'[Set priority value.]:value:({0..7})' \
                '--level-prefix=[Control whether level prefix shall be parsed.]:boolean:(1 0)' \
                ':Message'
        ;;
        systemd-cgls)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                '--no-pager[Do not pipe output into a pager]' \
                {-a,--all}'[Show all groups, including empty]' \
                '-k[Include kernel threads in output]' \
                ':cgroups:(cpuset cpu cpuacct memory devices freezer net_cls blkio)'
        ;;
        systemd-cgtop)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--version[Print version and exit]' \
                '(-c -m -i -t)-p[Order by path]' \
                '(-c -p -m -i)-t[Order by number of tasks]' \
                '(-m -p -i -t)-c[Order by CPU load]' \
                '(-c -p -i -t)-m[Order by memory load]' \
                '(-c -m -p -t)-i[Order by IO load]' \
                {-d,--delay=}'[Specify delay]' \
                {-n,--iterations=}'[Run for N iterations before exiting]' \
                {-b,--batch}'[Run in batch mode, accepting no input]' \
                '--depth=[Maximum traversal depth]'
        ;;
        systemd-delta)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                '--no-pager[Do not pipe output into a pager]' \
                '--diff=[Show a diff when overridden files differ]:boolean:(1 0)' \
                {-t,--type=}'[Only display a selected set of override types]:types:(masked equivalent redirected overridden unchanged)' \
                ':SUFFIX:(tmpfiles.d sysctl.d systemd/system)'
        ;;
        systemd-detect-virt)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                {-c,--container}'[Only detect whether we are run in a container]' \
                {-v,--vm}'[Only detect whether we are run in a VM]' \
                {-q,--quiet}"[Don't output anything, just set return value]"
        ;;
        systemd-inhibit)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                '--what=[Operations to inhibit]:options:(shutdown sleep idle handle-power-key handle-suspend-key handle-hibernate-key handle-lid-switch)' \
                '--who=[A descriptive string who is inhibiting]' \
                '--why=[A descriptive string why is being inhibited]' \
                '--mode=[One of block or delay]' \
                '--list[List active inhibitors]' \
                '*:commands:_systemd_inhibit_command'
        ;;
        systemd-machine-id-setup)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]'
        ;;
        systemd-notify)
            _arguments \
                {-h,--help}'[Show this help]' \
                '--version[Show package version]' \
                '--ready[Inform the init system about service start-up completion.]' \
                '--pid=[Inform the init system about the main PID of the daemon]' \
                '--status=[Send a free-form status string for the daemon to the init systemd]' \
                '--booted[Returns 0 if the system was booted up with systemd]' \
                '--readahead=[Controls disk read-ahead operations]:arguments:(cancel done noreply)'
        ;;
        systemd-nspawn)
            _arguments \
                {-h,--help}'[Show this help]' \
                {--directory=,-D}'[Directory to use as file system root for the namespace container. If omitted the current directory will be used.]:directories:_directories' \
                {--boot,-b}'[Automatically search for an init binary and invoke it instead of a shell or a user supplied program.]' \
                {--user=,-u}'[Run the command under specified user, create home directory and cd into it.]' \
                '--uuid=[Set the specified uuid for the container.]' \
                {--controllers=,-C}'[Makes the container appear in other hierarchies than the name=systemd:/ one. Takes a comma-separated list of controllers.]' \
                '--private-network[Turn off networking in the container. This makes all network interfaces unavailable in the container, with the exception of the loopback device.]' \
                '--read-only[Mount the root file system read only for the container.]' \
                '--capability=[List one or more additional capabilities to grant the container.]:capabilities:_systemd-nspawn' \
                "--link-journal=[Control whether the container's journal shall be made visible to the host system.]:options:(no, host, guest, auto)" \
                '-j[Equivalent to --link-journal=guest.]'
        ;;
        systemd-tmpfiles)
            _arguments \
                '--create[Create, set ownership/permissions based on the config files.]' \
                '--clean[Clean up all files and directories with an age parameter configured.]' \
                '--remove[All files and directories marked with r, R in the configuration files are removed.]' \
                '--prefix=[Only apply rules that apply to paths with the specified prefix.]' \
                '--help[Prints a short help text and exits.]' \
                '*::files:_files'
        ;;
        systemd-tty-ask-password-agent)
            _arguments \
                {-h,--help}'[Prints a short help text and exits.]' \
                '--version[Prints a short version string and exits.]' \
                '--list[Lists all currently pending system password requests.]' \
                '--query[Process all currently pending system password requests by querying the user on the calling TTY.]' \
                '--watch[Continuously process password requests.]' \
                '--wall[Forward password requests to wall(1).]' \
                '--plymouth[Ask question with plymouth(8).]' \
                '--console[Ask question on /dev/console.]'
        ;;
        *) _message 'eh?' ;;
    esac
}

_systemd-nspawn(){
    local -a _caps
    _caps=( CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
            CAP_FOWNER CAP_FSETID CAP_IPC_OWNER CAP_KILL CAP_LEASE CAP_LINUX_IMMUTABLE
            CAP_NET_BIND_SERVICE CAP_NET_BROADCAST CAP_NET_RAW CAP_SETGID CAP_SETFCAP CAP_SETPCAP
            CAP_SETUID CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SYS_NICE CAP_SYS_PTRACE CAP_SYS_TTY_CONFIG
            CAP_SYS_RESOURCE CAP_SYS_BOOT )
    _values -s , 'capabilities' "$_caps[@]"
}

_systemd_inhibit_command(){
    if (( CURRENT == 1 )); then
        compset -q
        _normal
    else
        local n=${words[(b:2:i)[^-]*]}
        if (( n <= CURRENT )); then
            compset -n $n
            _alternative \
                'files:file:_files' \
                'commands:command:_normal' && return 0
        fi
        _default
    fi

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
    )

    if (( CURRENT == 1 )); then
        _describe "options" _systemd_analyze_cmds
    else
        _message "no more options"
    fi
}

_hosts_or_user_at_host()
{
  _alternative \
    'users-hosts:: _user_at_host' \
    'hosts:: _hosts'
}

_outputmodes() {
    local -a _output_opts
    _output_opts=(short short-monotonic verbose export json json-pretty json-see cat)
    _describe -t output 'output mode' _output_opts || compadd "$@"
}


(( $+functions[_systemctl_command] )) || _systemctl_command()
{
  local -a _systemctl_cmds
  _systemctl_cmds=(
    "list-units:List units"
    "start:Start (activate) one or more units"
    "stop:Stop (deactivate) one or more units"
    "reload:Reload one or more units"
    "restart:Start or restart one or more units"
    "condrestart:Restart one or more units if active"
    "try-restart:Restart one or more units if active"
    "reload-or-restart:Reload one or more units if possible, otherwise start or restart"
    "force-reload:Reload one or more units if possible, otherwise restart if active"
    "hibernate:Hibernate the system"
    "hybrid-sleep:Hibernate and suspend the system"
    "reload-or-try-restart:Reload one or more units if possible, otherwise restart if active"
    "isolate:Start one unit and stop all others"
    "kill:Send signal to processes of a unit"
    "is-active:Check whether units are active"
    "is-failed:Check whether units are failed"
    "status:Show runtime status of one or more units"
    "show:Show properties of one or more units/jobs or the manager"
    "reset-failed:Reset failed state for all, one, or more units"
    "load:Load one or more units"
    "list-unit-files:List installed unit files"
    "enable:Enable one or more unit files"
    "disable:Disable one or more unit files"
    "reenable:Reenable one or more unit files"
    "preset:Enable/disable one or more unit files based on preset configuration"
    "help:Show documentation for specified units"
    "list-dependencies:Show unit dependency tree"
    "mask:Mask one or more units"
    "unmask:Unmask one or more units"
    "link:Link one or more units files into the search path"
    "is-enabled:Check whether unit files are enabled"
    "list-jobs:List jobs"
    "cancel:Cancel all, one, or more jobs"
    "dump:Dump server status"
    "snapshot:Create a snapshot"
    "delete:Remove one or more snapshots"
    "show-environment:Dump environment"
    "set-environment:Set one or more environment variables"
    "unset-environment:Unset one or more environment variables"
    "daemon-reload:Reload systemd manager configuration"
    "daemon-reexec:Reexecute systemd manager"
    "default:Enter system default mode"
    "rescue:Enter system rescue mode"
    "emergency:Enter system emergency mode"
    "halt:Shut down and halt the system"
    "suspend:Suspend the system"
    "poweroff:Shut down and power-off the system"
    "reboot:Shut down and reboot the system"
    "kexec:Shut down and reboot the system with kexec"
    "exit:Ask for user instance termination"
  )

  if (( CURRENT == 1 )); then
    _describe -t commands 'systemctl command' _systemctl_cmds || compadd "$@"
  else
    local curcontext="$curcontext"

    cmd="${${_systemctl_cmds[(r)$words[1]:*]%%:*}}"
    # Deal with any aliases
    case $cmd in
      condrestart) cmd="try-restart";;
      force-reload) cmd="reload-or-try-restart";;
    esac

    if (( $#cmd )); then
      curcontext="${curcontext%:*:*}:systemctl-${cmd}:"

      local update_policy
      zstyle -s ":completion:${curcontext}:" cache-policy update_policy
      if [[ -z "$update_policy" ]]; then
        zstyle ":completion:${curcontext}:" cache-policy _systemctl_caching_policy
      fi

      _call_function ret _systemctl_$cmd || _message 'no more arguments'
    else
      _message "unknown systemctl command: $words[1]"
    fi
    return ret
  fi
}

__systemctl()
{
  local -a _modes
  _modes=("--user" "--system")
  systemctl ${words:*_modes} --full --no-legend --no-pager "$@"
}


# Fills the unit list
_systemctl_all_units()
{
  if ( [[ ${+_sys_all_units} -eq 0 ]] || _cache_invalid SYS_ALL_UNITS ) &&
    ! _retrieve_cache SYS_ALL_UNITS;
  then
    _sys_all_units=( $(__systemctl list-units --all | { while read a b; do echo " $a"; done; }) )
    _store_cache SYS_ALL_UNITS _sys_all_units
  fi
}

# Fills the unit list including all file units
_systemctl_really_all_units()
{
  local -a all_unit_files;
  local -a really_all_units;
  if ( [[ ${+_sys_really_all_units} -eq 0 ]] || _cache_invalid SYS_REALLY_ALL_UNITS ) &&
    ! _retrieve_cache SYS_REALLY_ALL_UNITS;
  then
    all_unit_files=( $(__systemctl list-unit-files | { while read a b; do echo " $a"; done; }) )
    _systemctl_all_units
    really_all_units=($_sys_all_units $all_unit_files)
    _sys_really_all_units=(${(u)really_all_units})
    _store_cache SYS_REALLY_ALL_UNITS _sys_really_all_units
  fi
}

_filter_units_by_property() {
  local property=$1 value=$2 ; shift ; shift
  local -a units ; units=($*)
  local prop unit
  for ((i=1; $i <= ${#units[*]}; i++)); do
    # FIXME: "Failed to issue method call: Unknown unit" errors are ignored for
    # now (related to DBUS_ERROR_UNKNOWN_OBJECT). in the future, we need to
    # revert to calling 'systemctl show' once for all units, which is way
    # faster
    unit=${units[i]}
    prop=${(f)"$(_call_program units "$service show --no-pager --property="$property" ${unit} 2>/dev/null")"}
    if [[ "${prop}" = "$property=$value" ]]; then
      echo " ${unit}"
    fi
  done
}

_systemctl_active_units()  {_sys_active_units=(  $(__systemctl list-units          | { while read a b; do echo " $a"; done; }) )}
_systemctl_inactive_units(){_sys_inactive_units=($(__systemctl list-units --all    | { while read a b c d; do [[ $c == "inactive" || $c == "failed" ]] && echo " $a"; done; }) )}
_systemctl_failed_units()  {_sys_failed_units=(  $(__systemctl list-units --failed | { while read a b; do echo " $a"; done; }) )}
_systemctl_enabled_units() {_sys_enabled_units=( $(__systemctl list-unit-files     | { while read a b; do [[ $b == "enabled" ]] && echo " $a"; done; }) )}
_systemctl_disabled_units(){_sys_disabled_units=($(__systemctl list-unit-files     | { while read a b; do [[ $b == "disabled" ]] && echo " $a"; done; }) )}
_systemctl_masked_units()  {_sys_masked_units=(  $(__systemctl list-unit-files     | { while read a b; do [[ $b == "masked" ]] && echo " $a"; done; }) )}

# Completion functions for ALL_UNITS
for fun in is-active is-failed is-enabled status show mask preset help list-dependencies ; do
  (( $+functions[_systemctl_$fun] )) || _systemctl_$fun()
  {
    _systemctl_really_all_units
    compadd "$@" -a - _sys_really_all_units
  }
done

# Completion functions for ENABLED_UNITS
for fun in disable reenable ; do
  (( $+functions[_systemctl_$fun] )) || _systemctl_$fun()
  {
    _systemctl_enabled_units
    _systemctl_disabled_units
    compadd "$@" -a - _sys_enabled_units _sys_disabled_units
  }
done

# Completion functions for DISABLED_UNITS
(( $+functions[_systemctl_enable] )) || _systemctl_enable()
{
  _systemctl_disabled_units
  compadd "$@" -a - _sys_disabled_units
}

# Completion functions for FAILED_UNITS
(( $+functions[_systemctl_reset-failed] )) || _systemctl_reset-failed()
{
  _systemctl_failed_units
  compadd "$@" -a - _sys_failed_units || _message "no failed unit found"
}

# Completion functions for STARTABLE_UNITS
(( $+functions[_systemctl_start] )) || _systemctl_start()
{
  _systemctl_inactive_units
  compadd "$@" -a - _sys_inactive_units
}

# Completion functions for STOPPABLE_UNITS
for fun in stop kill try-restart condrestart ; do
  (( $+functions[_systemctl_$fun] )) || _systemctl_$fun()
  {
    _systemctl_active_units
    compadd "$@" - $( _filter_units_by_property CanStop yes \
      ${_sys_active_units[*]} )
  }
done

# Completion functions for ISOLATABLE_UNITS
(( $+functions[_systemctl_isolate] )) || _systemctl_isolate()
{
  _systemctl_all_units
  compadd "$@" - $( _filter_units_by_property AllowIsolate yes \
    ${_sys_all_units[*]} )
}

# Completion functions for RELOADABLE_UNITS
for fun in reload reload-or-try-restart force-reload ; do
  (( $+functions[_systemctl_$fun] )) || _systemctl_$fun()
  {
    _systemctl_active_units
    compadd "$@" - $( _filter_units_by_property CanReload yes \
      ${_sys_active_units[*]} )
  }
done

# Completion functions for RESTARTABLE_UNITS
for fun in restart reload-or-restart ; do
  (( $+functions[_systemctl_$fun] )) || _systemctl_$fun()
  {
    _systemctl_all_units
    compadd "$@" - $( _filter_units_by_property CanStart yes \
      ${_sys_all_units[*]} | while read line; do \
      [[ "$line" =~ \.device$ ]] || echo " $line"; \
      done )
  }
done

# Completion functions for MASKED_UNITS
(( $+functions[_systemctl_unmask] )) || _systemctl_unmask()
{
  _systemctl_masked_units
  compadd "$@" -a - _sys_masked_units || _message "no masked unit found"
}

# Completion functions for JOBS
(( $+functions[_systemctl_cancel] )) || _systemctl_cancel()
{
  compadd "$@" - $(__systemctl list-jobs \
    | cut -d' ' -f1  2>/dev/null ) || _message "no job found"
}

# Completion functions for SNAPSHOTS
(( $+functions[_systemctl_delete] )) || _systemctl_delete()
{
  compadd "$@" - $(__systemctl list-units --type snapshot --all \
    | cut -d' ' -f1  2>/dev/null ) || _message "no snapshot found"
}

# Completion functions for ENVS
for fun in set-environment unset-environment ; do
  (( $+functions[_systemctl_$fun] )) || _systemctl_$fun()
  {
    local fun=$0 ; fun=${fun##_systemctl_}
    local suf
    if [[ "${fun}" = "set-environment" ]]; then
      suf='-S='
    fi

    compadd "$@" ${suf} - $(systemctl show-environment \
      | while read line; do echo " ${line%%\=}";done )
  }
done

(( $+functions[_systemctl_link] )) || _systemctl_link() { _files }

# no systemctl completion for:
#    [STANDALONE]='daemon-reexec daemon-reload default dump
#                  emergency exit halt kexec list-jobs list-units
#                  list-unit-files poweroff reboot rescue show-environment'
#         [NAME]='snapshot load'

_systemctl_caching_policy()
{
  local _sysunits
  local -a oldcache

  # rebuild if cache is more than a day old
  oldcache=( "$1"(mh+1) )
  (( $#oldcache )) && return 0

  _sysunits=($(__systemctl --all | cut -d' ' -f1))

  if (( $#_sysunits )); then
    for unit in $_sysunits; do
      [[ "$unit" -nt "$1" ]] && return 0
    done
  fi

  return 1
}

_list_fields() {
    local -a journal_fields
    journal_fields=(MESSAGE{,_ID} PRIORITY CODE_{FILE,LINE,FUNC}
                    ERRNO SYSLOG_{FACILITY,IDENTIFIER,PID}
                    _{P,U,G}ID _COMM _EXE _CMDLINE
                    _AUDIT_{SESSION,LOGINUID}
                    _SYSTEMD_{CGROUP,SESSION,UNIT,OWNER_UID}
                    _SYSTEMD_USER_UNIT
                    _SELINUX_CONTEXT _SOURCE_REALTIME_TIMESTAMP
                    _{BOOT,MACHINE}_ID _HOSTNAME _TRANSPORT
                    _KERNEL_{DEVICE,SUBSYSTEM}
                    _UDEV_{SYSNAME,DEVNODE,DEVLINK}
                    __CURSOR __{REALTIME,MONOTONIC}_TIMESTAMP)
    _describe 'possible fields' journal_fields
}

_journal_none() {
    local -a _commands _files
    _commands=( ${(f)"$(_call_program commands "$service" -F _EXE 2>/dev/null)"} )
    _alternative : \
        'files:/dev files:_files -W /dev -P /dev/' \
        "commands:commands:($_commands[@])" \
        'fields:fields:_list_fields'
}

_journal_fields() {
    local -a _fields cmd
    cmd=("journalctl" "-F ${@[-1]}" "2>/dev/null" )
    _fields=( ${(f)"$(_call_program fields $cmd[@])"} )
    typeset -U _fields
    _describe 'possible values' _fields
}


_loginctl_all_sessions(){_sys_all_sessions=($(loginctl list-sessions | { while read a b; do echo " $a"; done; }) )}
_loginctl_all_users()   {_sys_all_users=(   $(loginctl list-users    | { while read a b; do echo " $a"; done; }) )}
_loginctl_all_seats()   {_sys_all_seats=(   $(loginctl list-seats    | { while read a b; do echo " $a"; done; }) )}

# Completion functions for SESSIONS
for fun in session-status show-session activate lock-session unlock-session terminate-session kill-session ; do
  (( $+functions[_loginctl_$fun] )) || _loginctl_$fun()
  {
    _loginctl_all_sessions
    compadd "$@" -a - _sys_all_sessions
  }
done

# Completion functions for USERS
for fun in user-status show-user enable-linger disable-linger terminate-user kill-user ; do
  (( $+functions[_loginctl_$fun] )) || _loginctl_$fun()
  {
    _loginctl_all_users
    compadd "$@" -a - _sys_all_users
  }
done

# Completion functions for SEATS
(( $+functions[_loginctl_seats] )) || _loginctl_seats()
{
  _loginctl_all_seats
  compadd "$@" -a - _sys_all_seats
}
for fun in seat-status show-seat terminate-seat ; do
  (( $+functions[_loginctl_$fun] )) || _loginctl_$fun()
  { _loginctl_seats }
done

# Completion functions for ATTACH
(( $+functions[_loginctl_attach] )) || _loginctl_attach()
{
  _loginctl_all_seats

  _arguments -w -C -S -s \
    ':seat:_loginctl_seats' \
    '*:device:_files'
}

# no loginctl completion for:
# [STANDALONE]='list-sessions list-users list-seats flush-devices'

(( $+functions[_loginctl_command] )) || _loginctl_command()
{
  local -a _loginctl_cmds
  _loginctl_cmds=(
    "list-sessions:List sessions"
    "session-status:Show session status"
    "show-session:Show properties of one or more sessions"
    "activate:Activate a session"
    "lock-session:Screen lock one or more sessions"
    "unlock-session:Screen unlock one or more sessions"
    "terminate-session:Terminate one or more sessions"
    "kill-session:Send signal to processes of a session"
    "list-users:List users"
    "user-status:Show user status"
    "show-user:Show properties of one or more users"
    "enable-linger:Enable linger state of one or more users"
    "disable-linger:Disable linger state of one or more users"
    "terminate-user:Terminate all sessions of one or more users"
    "kill-user:Send signal to processes of a user"
    "list-seats:List seats"
    "seat-status:Show seat status"
    "show-seat:Show properties of one or more seats"
    "attach:Attach one or more devices to a seat"
    "flush-devices:Flush all device associations"
    "terminate-seat:Terminate all sessions on one or more seats"
  )

  if (( CURRENT == 1 )); then
    _describe -t commands 'loginctl command' _loginctl_cmds || compadd "$@"
  else
    local curcontext="$curcontext"

    cmd="${${_loginctl_cmds[(r)$words[1]:*]%%:*}}"

    if (( $#cmd )); then
      curcontext="${curcontext%:*:*}:loginctl-${cmd}:"

      _call_function ret _loginctl_$cmd || _message 'no more arguments'
    else
      _message "unknown loginctl command: $words[1]"
    fi
    return ret
  fi
}

_hostnamectl_command() {
    local -a _hostnamectl_cmds
    _hostnamectl_cmds=(
        "status:Show current hostname settings"
        "set-hostname:Set system hostname"
        "set-icon-name:Set icon name for host"
    )
    if (( CURRENT == 1 )); then
        _describe -t commands 'hostnamectl commands' _hostnamectl_cmds || compadd "$@"
    else
        local curcontext="$curcontext"
        cmd="${${_hostnamectl_cmds[(r)$words[1]:*]%%:*}}"
        if (( $#cmd )); then
            [[ $cmd == status ]] && msg="no options" || msg="options for $cmd"
            _message "$msg"
        else
            _message "unknown hostnamectl command: $words[1]"
        fi
    fi
}

_localectl_set-locale() {
    local -a _confs _locales
    local expl suf
    _locales=( ${(f)"$(_call_program locales "$service" list-locales)"} )
    _confs=( ${${(f)"$(_call_program confs "locale 2>/dev/null")"}%\=*} )
    if [[ -prefix 1 *\= ]]; then
        local conf=${PREFIX%%\=*}
        compset -P1 '*='
        _wanted locales expl "locales configs" \
            _combination localeconfs  confs=$conf locales "$@" -
    else
        compadd -S '='  $_confs
    fi
}

_localectl_set-keymap() {
    local -a _keymaps
    _keymaps=( ${(f)"$(_call_program locales "$service" list-keymaps)"} )
    if (( CURRENT <= 3 )); then
        _describe keymaps _keymaps
    else
        _message "no more options"
    fi
}

_localectl_set-x11-keymap() {
    if (( $+commands[pkg-config] )); then
        local -a _file _layout _model _variant _options
        local _xorg_lst
        _xorg_lst=${"$($commands[pkg-config] xkeyboard-config --variable=xkb_base)"}
        _file=( ${(ps:\n\!:)"$(<$_xorg_lst/rules/xorg.lst)"} )
        _layout=( ${${${(M)${(f)_file[1]}:#  *}#  }%% *} )
        _model=( ${${${(M)${(f)_file[2]}:#  *}#  }%% *} )
        _variant=( ${${${(M)${(f)_file[3]}:#  *}#  }%% *} )
        _options=( ${${${(M)${(f)_file[4]}:#  *}#  }%% *} )
        #_layout=( ${(f)"$( echo $_file[1] | awk '/^  / {print $1}' )"} )
        #_model=( ${(f)"$(echo $_file[2] | awk '/^  / {print $1}')"} )
        #_variant=( ${(f)"$(echo $_file[3] | awk '/^  / {print $1}')"} )
        #_options=( ${(f)"$(echo ${_file[4]//:/\\:} | awk '/^  / {print $1}')"} )

        case $CURRENT in
            2) _describe layouts _layout ;;
            3) _describe models _model;;
            4) _describe variants _variant;;
            5) _describe options _options;;
            *) _message "no more options"
        esac
    fi
}


_localectl_command() {
    local -a _localectl_cmds
    _localectl_cmds=(
        'status:Show current locale settings'
        'set-locale:Set system locale'
        'list-locales:Show known locales'
        'set-keymap:Set virtual console keyboard mapping'
        'list-keymaps:Show known virtual console keyboard mappings'
        'set-x11-keymap:Set X11 keyboard mapping'
    )
    if (( CURRENT == 1 )); then
        _describe -t commands 'localectl command' _localectl_cmds
    else
        local curcontext="$curcontext"
        cmd="${${_localectl_cmds[(r)$words[1]:*]%%:*}}"
        if (( $+functions[_localectl_$cmd] )); then
            _localectl_$cmd
        else
            _message "no more options"
        fi
    fi
}

_timedatectl_set-timezone(){
    local -a _timezones
    _timezones=( ${(f)"$(_call_program timezones "${service}" list-timezones)"} )
    compadd "$_timezones[@]"
}

_timedatectl_set-time(){
    _message "YYYY-MM-DD HH:MM:SS"
}

_timedatectl_set-local-rtc(){
    local -a _options
    _options=(
        '0:Maintain RTC in universal time'
        '1:Maintain RTC in local time'
    )
    _describe options _options
}

_timedatectl_set-ntp(){
    local -a _options
    _options=(
        '0:Disable NTP based network time configuration'
        '1:Enable NTP based network time configuration'
    )
    _describe options _options
}

_timedatectl_command(){
    local -a _timedatectl_cmds
    _timedatectl_cmds=(
        'status:Show current time settings'
        'set-time:Set system time'
        'set-timezone:Set system timezone'
        'list-timezones:Show known timezones'
        'set-local-rtc:Control whether RTC is in local time'
        'set-ntp:Control whether NTP is enabled'
    )
    if (( CURRENT == 1 )); then
        _describe -t commands 'timedatectl command' _timedatectl_cmds
    else
        local curcontext="$curcontext"
        cmd="${${_timedatectl_cmds[(r)$words[1]:*]%%:*}}"
        if (( $#cmd )); then
            if (( $+functions[_timedatectl_$cmd] )); then
                _timedatectl_$cmd
            else
                _message "no more options"
            fi
        else
            _message "unknown timedatectl command: $words[1]"
        fi
    fi
}
_systemd-coredumpctl_command(){
    local -a _systemd_coredumpctl_cmds
    _systemd_coredumpctl_cmds=(
            'list:List available coredumps'
            'dump:Print coredump to std'
    )
    if (( CURRENT == 1 )); then
        _describe -t commands 'systemd-coredumpctl command' _systemd_coredumpctl_cmds
    else
        local curcontext="$curcontext"
        local -a _dumps
        cmd="${${_systemd_coredumpctl_cmds[(r)$words[1]:*]%%:*}}"
        if (( $#cmd  )); then
			# user can set zstyle ':completion:*:*:systemd-coredumpctl:*' sort no for coredumps to be ordered by date, otherwise they get ordered by pid
			_dumps=( "${(foa)$(systemd-coredumpctl list | awk 'BEGIN{OFS=":"} /^\s/ {sub(/[[ \t]+/, ""); print $5,$0}' 2>/dev/null)}" )
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

_udevadm_info(){
    _arguments \
        '--query=[Query the database for specified type of device data. It needs the --path or --name to identify the specified device.]:type:(name symlink path property all)' \
        '--path=[The devpath of the device to query.]:sys files:_files -P /sys/ -W /sys' \
        '--name=[The name of the device node or a symlink to query]:device files:_files -P /dev/ -W /dev' \
        '--root[Print absolute paths in name or symlink query.]' \
        '--attribute-walk[Print all sysfs properties of the specified device that can be used in udev rules to match the specified device]' \
        '--export[Print output as key/value pairs.]' \
        '--export-prefix=[Add a prefix to the key name of exported values.]:prefix' \
        '--device-id-of-file=[Print major/minor numbers of the underlying device, where the file lives on.]:files:_udevadm_mounts' \
        '--export-db[Export the content of the udev database.]' \
        '--cleanup-db[Cleanup the udev database.]'
}

_udevadm_trigger(){
    _arguments \
        '--verbose[Print the list of devices which will be triggered.]' \
        '--dry-run[Do not actually trigger the event.]' \
        '--type=[Trigger a specific type of devices.]:types:(devices subsystems failed)' \
        '--action=[Type of event to be triggered.]:actions:(add change remove)' \
        '--subsystem-match=[Trigger events for devices which belong to a matching subsystem.]' \
        '--subsystem-nomatch=[Do not trigger events for devices which belong to a matching subsystem.]' \
        '--attr-match=attribute=[Trigger events for devices with a matching sysfs attribute.]' \
        '--attr-nomatch=attribute=[Do not trigger events for devices with a matching sysfs attribute.]' \
        '--property-match=[Trigger events for devices with a matching property value.]' \
        '--tag-match=property[Trigger events for devices with a matching tag.]' \
        '--sysname-match=[Trigger events for devices with a matching sys device name.]' \
        '--parent-match=[Trigger events for all children of a given device.]'
}

_udevadm_settle(){
    _arguments \
       '--timeout=[Maximum number of seconds to wait for the event queue to become empty.]' \
       '--seq-start=[Wait only for events after the given sequence number.]' \
       '--seq-end=[Wait only for events before the given sequence number.]' \
       '--exit-if-exists=[Stop waiting if file exists.]:files:_files' \
       '--quiet[Do not print any output, like the remaining queue entries when reaching the timeout.]' \
       '--help[Print help text.]'
}

_udevadm_control(){
    _arguments \
        '--exit[Signal and wait for systemd-udevd to exit.]' \
        '--log-priority=[Set the internal log level of systemd-udevd.]:priorities:(err info debug)' \
        '--stop-exec-queue[Signal systemd-udevd to stop executing new events. Incoming events will be queued.]' \
        '--start-exec-queue[Signal systemd-udevd to enable the execution of events.]' \
        '--reload[Signal systemd-udevd to reload the rules files and other databases like the kernel module index.]' \
        '--property=[Set a global property for all events.]' \
        '--children-max=[Set the maximum number of events.]' \
        '--timeout=[The maximum number of seconds to wait for a reply from systemd-udevd.]' \
        '--help[Print help text.]'
}

_udevadm_monitor(){
    _arguments \
        '--kernel[Print the kernel uevents.]' \
        '--udev[Print the udev event after the rule processing.]' \
        '--property[Also print the properties of the event.]' \
        '--subsystem-match=[Filter events by subsystem/\[devtype\].]' \
        '--tag-match=[Filter events by property.]' \
        '--help[Print help text.]'
}

_udevadm_test(){
    _arguments \
        '--action=[The action string.]:actions:(add change remove)' \
        '--subsystem=[The subsystem string.]' \
        '--help[Print help text.]' \
        '*::devpath:_files -P /sys/ -W /sys'
}

_udevadm_test-builtin(){
    if (( CURRENT == 2 )); then
    _arguments \
        '--help[Print help text]' \
        '*::builtins:(blkid btrfs hwdb input_id kmod path_id usb_id uaccess)'
    elif  (( CURRENT == 3 )); then
        _arguments \
            '--help[Print help text]' \
            '*::syspath:_files -P /sys -W /sys'
    else
        _arguments \
            '--help[Print help text]'
    fi
}

_udevadm_mounts(){
  local dev_tmp dpath_tmp mp_tmp mline

    tmp=( "${(@f)$(< /etc/mtab)}" )
    dev_tmp=( "${(@)${(@)tmp%% *}:#none}" )
    mp_tmp=( "${(@)${(@)tmp#* }%% *}" )

  local MATCH
  mp_tmp=("${(@q)mp_tmp//(#m)\\[0-7](#c3)/${(#)$(( 8#${MATCH[2,-1]} ))}}")
  dpath_tmp=( "${(@Mq)dev_tmp:#/*}" )
  dev_tmp=( "${(@q)dev_tmp:#/*}" )

  _alternative \
    'device-paths: device path:compadd -a dpath_tmp' \
    'directories:mount point:compadd -a mp_tmp'
}


_udevadm_command(){
    local -a _udevadm_cmds
    _udevadm_cmds=(
        'info:query sysfs or the udev database'
        'trigger:request events from the kernel'
        'settle:wait for the event queue to finish'
        'control:control the udev daemon'
        'monitor:listen to kernel and udev events'
        'test:test an event run'
        'test-builtin:test a built-in command'
    )

    if ((CURRENT == 1)); then
        _describe -t commands 'udevadm commands' _udevadm_cmds
    else
        local curcontext="$curcontext"
        cmd="${${_udevadm_cmds[(r)$words[1]:*]%%:*}}"
        if (($#cmd)); then
            if (( $+functions[_udevadm_$cmd] )); then
                _udevadm_$cmd
            else
                _message "no options for $cmd"
            fi
        else
            _message "no more options"
        fi
    fi
}

_ctls "$@"

#vim: set ft=zsh sw=4 ts=4 et
