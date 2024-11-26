---
title: What Settings Are Currently Available For Transient Units?
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# What Settings Are Currently Available For Transient Units?

Our intention is to make all settings that are available as unit file settings
also available for transient units, through the D-Bus API. At the moment,
device, swap, and target units are not supported at all as transient units, but
others are pretty well supported.

The lists below contain all settings currently available in unit files. The
ones currently available in transient units are prefixed with `✓`.

## Generic Unit Settings

Most generic unit settings are available for transient units.

```
✓ Description=
✓ Documentation=
✓ SourcePath=
✓ Requires=
✓ Requisite=
✓ Wants=
✓ BindsTo=
✓ Conflicts=
✓ Before=
✓ After=
✓ OnFailure=
✓ PropagatesReloadTo=
✓ ReloadPropagatedFrom=
✓ PartOf=
✓ Upholds=
✓ JoinsNamespaceOf=
✓ RequiresMountsFor=
✓ StopWhenUnneeded=
✓ RefuseManualStart=
✓ RefuseManualStop=
✓ AllowIsolate=
✓ DefaultDependencies=
✓ OnFailureJobMode=
✓ IgnoreOnIsolate=
✓ JobTimeoutSec=
✓ JobRunningTimeoutSec=
✓ JobTimeoutAction=
✓ JobTimeoutRebootArgument=
✓ StartLimitIntervalSec=
✓ StartLimitBurst=
✓ StartLimitAction=
✓ FailureAction=
✓ SuccessAction=
✓ FailureActionExitStatus=
✓ SuccessActionExitStatus=
✓ RebootArgument=
✓ ConditionPathExists=
✓ ConditionPathExistsGlob=
✓ ConditionPathIsDirectory=
✓ ConditionPathIsSymbolicLink=
✓ ConditionPathIsMountPoint=
✓ ConditionPathIsReadWrite=
✓ ConditionDirectoryNotEmpty=
✓ ConditionFileNotEmpty=
✓ ConditionFileIsExecutable=
✓ ConditionNeedsUpdate=
✓ ConditionFirstBoot=
✓ ConditionKernelCommandLine=
✓ ConditionKernelVersion=
✓ ConditionArchitecture=
✓ ConditionFirmware=
✓ ConditionVirtualization=
✓ ConditionSecurity=
✓ ConditionCapability=
✓ ConditionHost=
✓ ConditionACPower=
✓ ConditionUser=
✓ ConditionGroup=
✓ ConditionControlGroupController=
✓ AssertPathExists=
✓ AssertPathExistsGlob=
✓ AssertPathIsDirectory=
✓ AssertPathIsSymbolicLink=
✓ AssertPathIsMountPoint=
✓ AssertPathIsReadWrite=
✓ AssertDirectoryNotEmpty=
✓ AssertFileNotEmpty=
✓ AssertFileIsExecutable=
✓ AssertNeedsUpdate=
✓ AssertFirstBoot=
✓ AssertKernelCommandLine=
✓ AssertKernelVersion=
✓ AssertArchitecture=
✓ AssertVirtualization=
✓ AssertSecurity=
✓ AssertCapability=
✓ AssertHost=
✓ AssertACPower=
✓ AssertUser=
✓ AssertGroup=
✓ AssertControlGroupController=
✓ CollectMode=
```

## Execution-Related Settings

All execution-related settings are available for transient units.

```
✓ WorkingDirectory=
✓ RootDirectory=
✓ RootImage=
✓ User=
✓ Group=
✓ SupplementaryGroups=
✓ Nice=
✓ OOMScoreAdjust=
✓ CoredumpFilter=
✓ IOSchedulingClass=
✓ IOSchedulingPriority=
✓ CPUSchedulingPolicy=
✓ CPUSchedulingPriority=
✓ CPUSchedulingResetOnFork=
✓ CPUAffinity=
✓ UMask=
✓ Environment=
✓ EnvironmentFile=
✓ PassEnvironment=
✓ UnsetEnvironment=
✓ DynamicUser=
✓ RemoveIPC=
✓ StandardInput=
✓ StandardOutput=
✓ StandardError=
✓ StandardInputText=
✓ StandardInputData=
✓ TTYPath=
✓ TTYReset=
✓ TTYVHangup=
✓ TTYVTDisallocate=
✓ TTYRows=
✓ TTYColumns=
✓ SyslogIdentifier=
✓ SyslogFacility=
✓ SyslogLevel=
✓ SyslogLevelPrefix=
✓ LogLevelMax=
✓ LogExtraFields=
✓ LogFilterPatterns=
✓ LogRateLimitIntervalSec=
✓ LogRateLimitBurst=
✓ SecureBits=
✓ CapabilityBoundingSet=
✓ AmbientCapabilities=
✓ TimerSlackNSec=
✓ NoNewPrivileges=
✓ KeyringMode=
✓ ProtectProc=
✓ ProcSubset=
✓ SystemCallFilter=
✓ SystemCallArchitectures=
✓ SystemCallErrorNumber=
✓ SystemCallLog=
✓ MemoryDenyWriteExecute=
✓ RestrictNamespaces=
✓ RestrictRealtime=
✓ RestrictSUIDSGID=
✓ RestrictAddressFamilies=
✓ RootHash=
✓ RootHashSignature=
✓ RootVerity=
✓ LockPersonality=
✓ LimitCPU=
✓ LimitFSIZE=
✓ LimitDATA=
✓ LimitSTACK=
✓ LimitCORE=
✓ LimitRSS=
✓ LimitNOFILE=
✓ LimitAS=
✓ LimitNPROC=
✓ LimitMEMLOCK=
✓ LimitLOCKS=
✓ LimitSIGPENDING=
✓ LimitMSGQUEUE=
✓ LimitNICE=
✓ LimitRTPRIO=
✓ LimitRTTIME=
✓ ReadWritePaths=
✓ ReadOnlyPaths=
✓ InaccessiblePaths=
✓ BindPaths=
✓ BindReadOnlyPaths=
✓ TemporaryFileSystem=
✓ PrivateTmp=
✓ PrivateDevices=
✓ PrivateMounts=
✓ ProtectKernelTunables=
✓ ProtectKernelModules=
✓ ProtectKernelLogs=
✓ ProtectControlGroups=
✓ PrivateNetwork=
✓ PrivateUsers=
✓ ProtectSystem=
✓ ProtectHome=
✓ ProtectClock=
✓ MountFlags=
✓ MountAPIVFS=
✓ Personality=
✓ RuntimeDirectoryPreserve=
✓ RuntimeDirectoryMode=
✓ RuntimeDirectory=
✓ StateDirectoryMode=
✓ StateDirectory=
✓ CacheDirectoryMode=
✓ CacheDirectory=
✓ LogsDirectoryMode=
✓ LogsDirectory=
✓ ConfigurationDirectoryMode=
✓ ConfigurationDirectory=
✓ PAMName=
✓ IgnoreSIGPIPE=
✓ UtmpIdentifier=
✓ UtmpMode=
✓ SELinuxContext=
✓ SmackProcessLabel=
✓ AppArmorProfile=
✓ Slice=
```

## Resource Control Settings

All cgroup/resource control settings are available for transient units

```
✓ CPUAccounting=
✓ CPUWeight=
✓ StartupCPUWeight=
✓ CPUShares=
✓ StartupCPUShares=
✓ CPUQuota=
✓ CPUQuotaPeriodSec=
✓ AllowedCPUs=
✓ StartupAllowedCPUs=
✓ AllowedMemoryNodes=
✓ StartupAllowedMemoryNodes=
✓ MemoryAccounting=
✓ DefaultMemoryMin=
✓ MemoryMin=
✓ DefaultMemoryLow=
✓ MemoryLow=
✓ MemoryHigh=
✓ MemoryMax=
✓ MemorySwapMax=
✓ MemoryLimit=
✓ DeviceAllow=
✓ DevicePolicy=
✓ IOAccounting=
✓ IOWeight=
✓ StartupIOWeight=
✓ IODeviceWeight=
✓ IOReadBandwidthMax=
✓ IOWriteBandwidthMax=
✓ IOReadIOPSMax=
✓ IOWriteIOPSMax=
✓ BlockIOAccounting=
✓ BlockIOWeight=
✓ StartupBlockIOWeight=
✓ BlockIODeviceWeight=
✓ BlockIOReadBandwidth=
✓ BlockIOWriteBandwidth=
✓ TasksAccounting=
✓ TasksMax=
✓ Delegate=
✓ DisableControllers=
✓ IPAccounting=
✓ IPAddressAllow=
✓ IPAddressDeny=
✓ ManagedOOMSwap=
✓ ManagedOOMMemoryPressure=
✓ ManagedOOMMemoryPressureLimit=
✓ ManagedOOMMemoryPressureDurationSec=
✓ ManagedOOMPreference=
✓ CoredumpReceive=
```

## Process Killing Settings

All process killing settings are available for transient units:

```
✓ SendSIGKILL=
✓ SendSIGHUP=
✓ KillMode=
✓ KillSignal=
✓ RestartKillSignal=
✓ FinalKillSignal=
✓ WatchdogSignal=
```

## Service Unit Settings

Most service unit settings are available for transient units.

```
✓ BusName=
✓ ExecCondition=
✓ ExecReload=
✓ ExecStart=
✓ ExecStartPost=
✓ ExecStartPre=
✓ ExecStop=
✓ ExecStopPost=
✓ ExitType=
✓ FileDescriptorStoreMax=
✓ GuessMainPID=
✓ NonBlocking=
✓ NotifyAccess=
✓ OOMPolicy=
✓ PIDFile=
✓ RemainAfterExit=
✓ Restart=
✓ RestartForceExitStatus=
✓ RestartPreventExitStatus=
✓ RestartSec=
✓ RootDirectoryStartOnly=
✓ RuntimeMaxSec=
✓ RuntimeRandomizedExtraSec=
  Sockets=
✓ SuccessExitStatus=
✓ TimeoutAbortSec=
✓ TimeoutSec=
✓ TimeoutStartFailureMode=
✓ TimeoutStartSec=
✓ TimeoutStopFailureMode=
✓ TimeoutStopSec=
✓ Type=
✓ USBFunctionDescriptors=
✓ USBFunctionStrings=
✓ WatchdogSec=
```

## Mount Unit Settings

All mount unit settings are available to transient units:

```
✓ What=
✓ Where=
✓ Options=
✓ Type=
✓ TimeoutSec=
✓ DirectoryMode=
✓ SloppyOptions=
✓ LazyUnmount=
✓ ForceUnmount=
✓ ReadWriteOnly=
```

## Automount Unit Settings

All automount unit setting is available to transient units:

```
✓ Where=
✓ DirectoryMode=
✓ TimeoutIdleSec=
```

## Timer Unit Settings

Most timer unit settings are available to transient units.

```
✓ OnActiveSec=
✓ OnBootSec=
✓ OnCalendar=
✓ OnClockChange=
✓ OnStartupSec=
✓ OnTimezoneChange=
✓ OnUnitActiveSec=
✓ OnUnitInactiveSec=
✓ Persistent=
✓ WakeSystem=
✓ RemainAfterElapse=
✓ AccuracySec=
✓ RandomizedDelaySec=
✓ FixedRandomDelay=
✓ DeferReactivation=
  Unit=
```

## Slice Unit Settings

Slice units are fully supported as transient units, but they have no settings
of their own beyond the generic unit and resource control settings.

## Scope Unit Settings

Scope units are fully supported as transient units (in fact they only exist as
such).

```
✓ RuntimeMaxSec=
✓ RuntimeRandomizedExtraSec=
✓ TimeoutStopSec=
```

## Socket Unit Settings

Most socket unit settings are available to transient units.

```
✓ ListenStream=
✓ ListenDatagram=
✓ ListenSequentialPacket=
✓ ListenFIFO=
✓ ListenNetlink=
✓ ListenSpecial=
✓ ListenMessageQueue=
✓ ListenUSBFunction=
✓ SocketProtocol=
✓ BindIPv6Only=
✓ Backlog=
✓ BindToDevice=
✓ ExecStartPre=
✓ ExecStartPost=
✓ ExecStopPre=
✓ ExecStopPost=
✓ TimeoutSec=
✓ SocketUser=
✓ SocketGroup=
✓ SocketMode=
✓ DirectoryMode=
✓ Accept=
✓ FlushPending=
✓ Writable=
✓ MaxConnections=
✓ MaxConnectionsPerSource=
✓ KeepAlive=
✓ KeepAliveTimeSec=
✓ KeepAliveIntervalSec=
✓ KeepAliveProbes=
✓ DeferAcceptSec=
✓ NoDelay=
✓ Priority=
✓ ReceiveBuffer=
✓ SendBuffer=
✓ IPTOS=
✓ IPTTL=
✓ Mark=
✓ PipeSize=
✓ FreeBind=
✓ Transparent=
✓ Broadcast=
✓ PassCredentials=
✓ PassSecurity=
✓ PassPacketInfo=
✓ TCPCongestion=
✓ ReusePort=
✓ MessageQueueMaxMessages=
✓ MessageQueueMessageSize=
✓ RemoveOnStop=
✓ Symlinks=
✓ FileDescriptorName=
  Service=
✓ TriggerLimitIntervalSec=
✓ TriggerLimitBurst=
✓ SmackLabel=
✓ SmackLabelIPIn=
✓ SmackLabelIPOut=
✓ SELinuxContextFromNet=
```

## Swap Unit Settings

Swap units are currently not available at all as transient units:

```
  What=
  Priority=
  Options=
  TimeoutSec=
```

## Path Unit Settings

Most path unit settings are available to transient units.

```
✓ PathExists=
✓ PathExistsGlob=
✓ PathChanged=
✓ PathModified=
✓ DirectoryNotEmpty=
  Unit=
✓ MakeDirectory=
✓ DirectoryMode=
```

## Install Section

The `[Install]` section is currently not available at all for transient units, and it probably doesn't even make sense.

```
  Alias=
  WantedBy=
  RequiredBy=
  Also=
  DefaultInstance=
```
