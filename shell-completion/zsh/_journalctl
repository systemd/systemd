#compdef journalctl

_list_fields() {
    local -a journal_fields
    journal_fields=(MESSAGE{,_ID} PRIORITY CODE_{FILE,LINE,FUNC}
                    ERRNO SYSLOG_{FACILITY,IDENTIFIER,PID}
                    _{P,U,G}ID _COMM _EXE _CMDLINE
                    _AUDIT_{SESSION,LOGINUID}
                    _SYSTEMD_{CGROUP,SESSION,UNIT,OWNER_UID}
                    _SYSTEMD_USER_UNIT USER_UNIT
                    _SELINUX_CONTEXT _SOURCE_REALTIME_TIMESTAMP
                    _{BOOT,MACHINE}_ID _HOSTNAME _TRANSPORT
                    _KERNEL_{DEVICE,SUBSYSTEM}
                    _UDEV_{SYSNAME,DEVNODE,DEVLINK}
                    __CURSOR __{REALTIME,MONOTONIC}_TIMESTAMP)
    case $_jrnl_none in
        yes) _values -s '=' 'possible fields' \
                "${journal_fields[@]}:value:_journal_fields ${words[CURRENT]%%=*}" ;;
        *)  _describe 'possible fields' journal_fields ;;
    esac
}

_journal_none() {
    local -a _commands _files _jrnl_none
    # Setting use-cache will slow this down considerably
    _commands=( ${"$(_call_program commands "$service $_sys_service_mgr -F _EXE" 2>/dev/null)"} )
    _jrnl_none='yes'
    _alternative : \
        'files:/dev files:_files -W /dev -P /dev/' \
        "commands:commands:($_commands[@])" \
        'fields:fields:_list_fields'
}

_journal_fields() {
    local -a _fields cmd
    cmd=("journalctl $_sys_service_mgr" "-F ${@[-1]}" "2>/dev/null" )
    _fields=$(_call_program fields $cmd[@])
    _fields=${_fields//'\'/'\\'}
    _fields=${_fields//':'/'\:'}
    _fields=( ${(f)_fields} )
    typeset -U _fields
    _describe 'possible values' _fields
}

_journal_boots() {
  local -a _bootid _previousboots
  _bootid=( ${(f)"$(_call_program bootid "$service -F _BOOT_ID")"}  )
  _previousboots=( -{1..${#_bootid}} )
  _alternative : \
    "offsets:boot offsets:compadd -a '_previousboots[1,-2]'" \
    "bootid:boot ids:compadd -a _bootid"
}

# Build arguments for "journalctl" to be used in completion.
# Use both --user and --system modes, they are not exclusive.
local -a _modes; _modes=(--user --system)
local -a _modes_with_arg; _modes_with_arg=(--directory -D --file -M --machine --root)
typeset -a _sys_service_mgr
local w k v i=0 n=$#words
while (( i++ < n )); do
    w=$words[$i]
    if (( $_modes[(I)$w] )); then
        _sys_service_mgr+=($w)
    else
        # Handle options with arguments. "--key=value" and "--key value".
        k=${w%%=*}
        if (( ${_modes_with_arg[(I)$k]} )); then
            v=${w#*=}
            if [[ "$k" != "$w" ]]; then
                # "--key=value" style.
                _sys_service_mgr+=($w)
            else
                # "--key value" style.
                _sys_service_mgr+=($w ${words[((++i))]})
            fi
        fi
    fi
done
_arguments -s \
    {-h,--help}'[Show this help]' \
    '--version[Show package version]' \
    '--no-pager[Do not pipe output into a pager]' \
    {-l,--full}'[Show long fields in full]' \
    {-a,--all}'[Show all fields, including long and unprintable]' \
    {-f,--follow}'[Follow journal]' \
    {-e,--pager-end}'[Jump to the end of the journal in the pager]' \
    {-n+,--lines=}'[Number of journal entries to show]:integer' \
    '--no-tail[Show all lines, even in follow mode]' \
    {-r,--reverse}'[Reverse output]' \
    {-o+,--output=}'[Change journal output mode]:output modes:_sd_outputmodes' \
    {-x,--catalog}'[Show explanatory texts with each log line]' \
    {-q,--quiet}"[Don't show privilege warning]" \
    {-m,--merge}'[Show entries from all available journals]' \
    {-b+,--boot=}'[Show data only from the specified boot or offset]::boot id or offset:_journal_boots' \
    '--list-boots[List boots ordered by time]' \
    {-k,--dmesg}'[Show only kernel messages from the current boot]' \
    {-u+,--unit=}'[Show data only from the specified unit]:units:_journal_fields _SYSTEMD_UNIT' \
    '--user-unit=[Show data only from the specified user session unit]:units:_journal_fields USER_UNIT' \
    {-p+,--priority=}'[Show only messages within the specified priority range]:priority:_journal_fields PRIORITY' \
    {-t+,--identifier=}'[Show only messages with the specified syslog identifier]:identifier:_journal_fields SYSLOG_IDENTIFIER' \
    {-c+,--cursor=}'[Start showing entries from the specified cursor]:cursors:_journal_fields __CURSORS' \
    '--after-cursor=[Start showing entries from after the specified cursor]:cursors:_journal_fields __CURSORS' \
    '--since=[Start showing entries on or newer than the specified date]:YYYY-MM-DD HH\:MM\:SS' \
    '--until=[Stop showing entries on or older than the specified date]:YYYY-MM-DD HH\:MM\:SS' \
    {-F,--field=}'[List all values a certain field takes]:Fields:_list_fields' \
    '--system[Show system and kernel messages]' \
    '--user[Show messages from user services]' \
    '(--directory -D -M --machine --root --file)'{-M+,--machine=}'[Operate on local container]:machines:_sd_machines' \
    '(--directory -D -M --machine --root --file)'{-D+,--directory=}'[Show journal files from directory]:directories:_directories' \
    '(--directory -D -M --machine --root --file)''--root=[Operate on catalog hierarchy under specified directory]:directories:_directories' \
    '(--directory -D -M --machine --root)--file=[Operate on specified journal files]:file:_files' \
    '--new-id128[Generate a new 128 Bit ID]' \
    '--header[Show journal header information]' \
    '--disk-usage[Show total disk usage]' \
    '--list-catalog[List messages in catalog]' \
    '--dump-catalog[Dump messages in catalog]' \
    '--update-catalog[Update binary catalog database]' \
    '--setup-keys[Generate a new FSS key pair]' \
    '--force[Force recreation of the FSS keys]' \
    '--interval=[Time interval for changing the FSS sealing key]:time interval' \
    '--verify[Verify journal file consistency]' \
    '--verify-key=[Specify FSS verification key]:FSS key' \
    '*::default: _journal_none'
