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
✓ SourcePath=
✓ OnFailureJobMode=
✓ JobTimeoutAction=
✓ JobTimeoutRebootArgument=
✓ StartLimitAction=
✓ FailureAction=
✓ SuccessAction=
✓ RebootArgument=
✓ CollectMode=
✓ StopWhenUnneeded=
✓ RefuseManualStart=
✓ RefuseManualStop=
✓ AllowIsolate=
✓ IgnoreOnIsolate=
✓ SurviveFinalKillSignal=
✓ DefaultDependencies=
✓ JobTimeoutSec=
✓ JobRunningTimeoutSec=
✓ StartLimitIntervalSec=
✓ StartLimitBurst=
✓ SuccessActionExitStatus=
✓ FailureActionExitStatus=
✓ Documentation=
✓ RequiresMountsFor=
✓ WantsMountsFor=
✓ Markers=
✓ Requires=
✓ Requisite=
✓ Wants=
✓ BindsTo=
✓ PartOf=
✓ Upholds=
✓ RequiredBy=
✓ RequisiteOf=
✓ WantedBy=
✓ BoundBy=
✓ UpheldBy=
✓ ConsistsOf=
✓ Conflicts=
✓ ConflictedBy=
✓ Before=
✓ After=
✓ OnSuccess=
✓ OnSuccessOf=
✓ OnFailure=
✓ OnFailureOf=
✓ Triggers=
✓ TriggeredBy=
✓ PropagatesReloadTo=
✓ ReloadPropagatedFrom=
✓ PropagatesStopTo=
✓ StopPropagatedFrom=
✓ JoinsNamespaceOf=
✓ References=
✓ ReferencedBy=
✓ InSlice=
✓ SliceOf=
✓ ConditionArchitecture=
✓ ConditionFirmware=
✓ ConditionVirtualization=
✓ ConditionHost=
✓ ConditionKernelCommandLine=
✓ ConditionVersion=
✓ ConditionCredential=
✓ ConditionSecurity=
✓ ConditionCapability=
✓ ConditionACPower=
✓ ConditionNeedsUpdate=
✓ ConditionFirstBoot=
✓ ConditionPathExists=
✓ ConditionPathExistsGlob=
✓ ConditionPathIsDirectory=
✓ ConditionPathIsSymbolicLink=
✓ ConditionPathIsMountPoint=
✓ ConditionPathIsReadWrite=
✓ ConditionPathIsEncrypted=
✓ ConditionDirectoryNotEmpty=
✓ ConditionFileNotEmpty=
✓ ConditionFileIsExecutable=
✓ ConditionUser=
✓ ConditionGroup=
✓ ConditionControlGroupController=
✓ ConditionCPUs=
✓ ConditionMemory=
✓ ConditionEnvironment=
✓ ConditionCPUFeature=
✓ ConditionOSRelease=
✓ ConditionMemoryPressure=
✓ ConditionCPUPressure=
✓ ConditionIOPressure=
✓ ConditionKernelModuleLoaded=
✓ AssertArchitecture=
✓ AssertFirmware=
✓ AssertVirtualization=
✓ AssertHost=
✓ AssertKernelCommandLine=
✓ AssertVersion=
✓ AssertCredential=
✓ AssertSecurity=
✓ AssertCapability=
✓ AssertACPower=
✓ AssertNeedsUpdate=
✓ AssertFirstBoot=
✓ AssertPathExists=
✓ AssertPathExistsGlob=
✓ AssertPathIsDirectory=
✓ AssertPathIsSymbolicLink=
✓ AssertPathIsMountPoint=
✓ AssertPathIsReadWrite=
✓ AssertPathIsEncrypted=
✓ AssertDirectoryNotEmpty=
✓ AssertFileNotEmpty=
✓ AssertFileIsExecutable=
✓ AssertUser=
✓ AssertGroup=
✓ AssertControlGroupController=
✓ AssertCPUs=
✓ AssertMemory=
✓ AssertEnvironment=
✓ AssertCPUFeature=
✓ AssertOSRelease=
✓ AssertMemoryPressure=
✓ AssertCPUPressure=
✓ AssertIOPressure=
✓ AssertKernelModuleLoaded=
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
✓ StateDirectoryAccounting=
✓ StateDirectoryQuota=
✓ StateDirectory=
✓ CacheDirectoryMode=
✓ CacheDirectoryAccounting=
✓ CacheDirectoryQuota=
✓ CacheDirectory=
✓ LogsDirectoryMode=
✓ LogsDirectoryAccounting=
✓ LogsDirectoryQuota=
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
✓ DevicePolicy=
✓ Slice=
✓ ManagedOOMSwap=
✓ ManagedOOMMemoryPressure=
✓ ManagedOOMPreference=
✓ MemoryPressureWatch=
✓ DelegateSubgroup=
✓ ManagedOOMMemoryPressureLimit=
✓ MemoryAccounting=
✓ MemoryZSwapWriteback=
✓ IOAccounting=
✓ TasksAccounting=
✓ IPAccounting=
✓ CoredumpReceive=
✓ CPUWeight=
✓ StartupCPUWeight=
✓ IOWeight=
✓ StartupIOWeight=
✓ AllowedCPUs=
✓ StartupAllowedCPUs=
✓ AllowedMemoryNodes=
✓ StartupAllowedMemoryNodes=
✓ DisableControllers=
✓ Delegate=
✓ MemoryMin=
✓ DefaultMemoryLow=
✓ DefaultMemoryMin=
✓ MemoryLow=
✓ MemoryHigh=
✓ MemoryMax=
✓ MemorySwapMax=
✓ MemoryZSwapMax=
✓ TasksMax=
✓ CPUQuota=
✓ CPUQuotaPeriodSec=
✓ DeviceAllow=
✓ IODeviceWeight=
✓ IODeviceLatencyTargetSec=
✓ IPAddressAllow=
✓ IPAddressDeny=
✓ IPIngressFilterPath=
✓ IPEgressFilterPath=
✓ BPFProgram=
✓ SocketBindAllow=
✓ SocketBindDeny=
✓ MemoryPressureThresholdSec=
✓ NFTSet=
✓ ManagedOOMMemoryPressureDurationSec=
✓ IOReadBandwidthMax=
✓ IOWriteBandwidthMax=
✓ IOReadIOPSMax=
✓ IOWriteIOPSMax=
```

## Process Killing Settings

All process killing settings are available for transient units:

```
✓ KillMode=
✓ SendSIGHUP=
✓ SendSIGKILL=
✓ KillSignal=
✓ RestartKillSignal=
✓ FinalKillSignal=
✓ WatchdogSignal=
✓ ReloadSignal=
```

## Service Unit Settings

Most service unit settings are available for transient units.

```
✓ PIDFile=
✓ Type=
✓ ExitType=
✓ Restart=
✓ RestartMode=
✓ BusName=
✓ NotifyAccess=
✓ USBFunctionDescriptors=
✓ USBFunctionStrings=
✓ OOMPolicy=
✓ TimeoutStartFailureMode=
✓ TimeoutStopFailureMode=
✓ FileDescriptorStorePreserve=
✓ PermissionsStartOnly=
✓ RootDirectoryStartOnly=
✓ RemainAfterExit=
✓ GuessMainPID=
✓ RestartSec=
✓ RestartMaxDelaySec=
✓ TimeoutStartSec=
✓ TimeoutStopSec=
✓ TimeoutAbortSec=
✓ RuntimeMaxSec=
✓ RuntimeRandomizedExtraSec=
✓ WatchdogSec=
✓ TimeoutSec=
✓ FileDescriptorStoreMax=
✓ RestartSteps=
✓ ExecCondition=
✓ ExecStartPre=
✓ ExecStart=
✓ ExecStartPost=
✓ ExecConditionEx=
✓ ExecStartPreEx=
✓ ExecStartEx=
✓ ExecStartPostEx=
✓ ExecReload=
✓ ExecStop=
✓ ExecStopPost=
✓ ExecReloadEx=
✓ ExecStopEx=
✓ ExecStopPostEx=
✓ RestartPreventExitStatus=
✓ RestartForceExitStatus=
✓ SuccessExitStatus=
✓ OpenFile=
  Socket=
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
✓ ReadwriteOnly=
```

## Automount Unit Settings

All automount unit setting is available to transient units:

```
✓ Where=
✓ ExtraOptions=
✓ DirectoryMode=
✓ TimeoutIdleSec=
```

## Timer Unit Settings

Most timer unit settings are available to transient units.

```
✓ WakeSystem=
✓ RemainAfterElapse=
✓ Persistent=
✓ OnTimezoneChange=
✓ OnClockChange=
✓ FixedRandomDelay=
✓ DeferReactivation=
✓ AccuracySec=
✓ RandomizedDelaySec=
✓ OnActiveSec=
✓ OnBootSec=
✓ OnStartupSec=
✓ OnUnitActiveSec=
✓ OnUnitInactiveSec=
✓ OnCalendar=
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
✓ User=
✓ Group=
✓ OOMPolicy=
```

## Socket Unit Settings

Most socket unit settings are available to transient units.

```
✓ Accept=
✓ FlushPending=
✓ Writable=
✓ KeepAlive=
✓ NoDelay=
✓ FreeBind=
✓ Transparent=
✓ Broadcast=
✓ PassCredentials=
✓ PassFileDescriptorsToExec=
✓ PassSecurity=
✓ PassPacketInfo=
✓ ReusePort=
✓ RemoveOnStop=
✓ SELinuxContextFromNet=
✓ Priority=
✓ IPTTL=
✓ Mark=
✓ IPTOS=
✓ Backlog=
✓ MaxConnections=
✓ MaxConnectionsPerSource=
✓ KeepAliveProbes=
✓ TriggerLimitBurst=
✓ PollLimitBurst=
✓ SocketMode=
✓ DirectoryMode=
✓ MessageQueueMaxMessages=
✓ MessageQueueMessageSize=
✓ TimeoutSec=
✓ KeepAliveTimeSec=
✓ KeepAliveIntervalSec=
✓ DeferAcceptSec=
✓ DeferTrigger=
✓ DeferTriggerMaxSec=
✓ TriggerLimitIntervalSec=
✓ PollLimitIntervalSec=
✓ ReceiveBuffer=
✓ SendBuffer=
✓ PipeSize=
✓ ExecStartPre=
✓ ExecStartPost=
✓ ExecReload=
✓ ExecStopPost=
✓ SmackLabel=
✓ SmackLabelIPIn=
✓ SmackLabelIPOut=
✓ TCPCongestion=
✓ BindToDevice=
✓ BindIPv6Only=
✓ FileDescriptorName=
✓ SocketUser=
✓ SocketGroup=
✓ Timestamping=
✓ Symlinks=
✓ SocketProtocol=
✓ ListenStream=
✓ ListenDatagram=
✓ ListenSequentialPacket=
✓ ListenNetlink=
✓ ListenSpecial=
✓ ListenMessageQueue=
✓ ListenFIFO=
✓ ListenUSBFunction=
  Service=
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
✓ MakeDirectory=
✓ DirectoryMode=
✓ PathExists=
✓ PathExistsGlob=
✓ PathChanged=
✓ PathModified=
✓ DirectoryNotEmpty=
✓ TriggerLimitBurst=
✓ PollLimitBurst=
✓ TriggerLimitIntervalSec=
✓ PollLimitIntervalSec=
  Unit=
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
