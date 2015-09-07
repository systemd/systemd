#compdef systemd-run

__systemctl() {
        local -a _modes
        _modes=("--user" "--system")
        systemctl ${words:*_modes} --full --no-legend --no-pager "$@" 2>/dev/null
}

__get_slices () {
        __systemctl list-units --all -t slice \
        | { while read -r a b; do echo $a; done; };
}

__slices () {
        local -a _slices
        _slices=(${(fo)"$(__get_slices)"})
        typeset -U _slices
        _describe 'slices' _slices
}

_arguments \
        {-h,--help}'[Show help message]' \
        '--version[Show package version]' \
        '--user[Run as user unit]' \
        {-H+,--host=}'[Operate on remote host]:[user@]host:_sd_hosts_or_user_at_host' \
        {-M+,--machine=}'[Operate on local container]:machines:_sd_machines' \
        '--scope[Run this as scope rather than service]' \
        '--unit=[Run under the specified unit name]:unit name' \
        {-p+,--property=}'[Set unit property]:NAME=VALUE:(( \
                CPUAccounting= MemoryAccounting= BlockIOAccounting= SendSIGHUP= \
                SendSIGKILL= MemoryLimit= CPUShares= BlockIOWeight= User= Group= \
                DevicePolicy= KillMode= DeviceAllow= BlockIOReadBandwidth= \
                BlockIOWriteBandwidth= BlockIODeviceWeight= Nice= Environment= \
                KillSignal= LimitCPU= LimitFSIZE= LimitDATA= LimitSTACK= \
                LimitCORE= LimitRSS= LimitNOFILE= LimitAS= LimitNPROC= \
                LimitMEMLOCK= LimitLOCKS= LimitSIGPENDING= LimitMSGQUEUE= \
                LimitNICE= LimitRTPRIO= LimitRTTIME= PrivateTmp= PrivateDevices= \
                PrivateNetwork= NoNewPrivileges= WorkingDirectory= RootDirectory= \
                TTYPath= SyslogIdentifier= SyslogLevelPrefix= SyslogLevel= \
                SyslogFacility= TimerSlackNSec= OOMScoreAdjust= ReadWriteDirectories= \
                ReadOnlyDirectories= InaccessibleDirectories= EnvironmentFile= \
                ProtectSystem= ProtectHome= RuntimeDirectory= PassEnvironment= \
                ))' \
        '--description=[Description for unit]:description' \
        '--slice=[Run in the specified slice]:slices:__slices' \
        {-r,--remain-after-exit}'[Leave service around until explicitly stopped]' \
        '--send-sighup[Send SIGHUP when terminating]' \
        '--service-type=[Service type]:type:(simple forking oneshot dbus notify idle)' \
        '--uid=[Run as system user]:user:_users' \
        '--gid=[Run as system group]:group:_groups' \
        '--nice=[Nice level]:nice level' \
        '--setenv=[Set environment]:NAME=VALUE' \
        '--on-active=[Run after SEC seconds]:SEC' \
        '--on-boot=[Run after SEC seconds from machine was booted up]:SEC' \
        '--on-statup=[Run after SEC seconds from systemd was first started]:SEC' \
        '--on-unit-active=[Run after SEC seconds from the last activation]:SEC' \
        '--on-unit-inactive=[Run after SEC seconds from the last deactivation]:SEC' \
        '--on-calendar=[Realtime timer]:SPEC' \
        '--timer-property=[Set timer unit property]:NAME=VALUE' \
        '*::command:_command'
