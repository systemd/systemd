/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"        /* IWYU pragma: export */
#include "forward.h"                    /* IWYU pragma: export */
#include "unit-def.h"                   /* IWYU pragma: export */

typedef enum CGroupDevicePermissions CGroupDevicePermissions;
typedef enum CGroupDevicePolicy CGroupDevicePolicy;
typedef enum ExecCleanMask ExecCleanMask;
typedef enum ExecPreserveMode ExecPreserveMode;
typedef enum FreezerAction FreezerAction;
typedef enum JobResult JobResult;
typedef enum JobState JobState;
typedef enum JobType JobType;
typedef enum ManagerState ManagerState;
typedef enum TransactionAddFlags TransactionAddFlags;
typedef enum UnitDependencyAtom UnitDependencyAtom;
typedef enum UnitWriteFlags UnitWriteFlags;

typedef struct ActivationDetails ActivationDetails;
typedef struct BindMount BindMount;
typedef struct CGroupBPFForeignProgram CGroupBPFForeignProgram;
typedef struct CGroupContext CGroupContext;
typedef struct CGroupDeviceAllow CGroupDeviceAllow;
typedef struct CGroupIODeviceLatency CGroupIODeviceLatency;
typedef struct CGroupIODeviceLimit CGroupIODeviceLimit;
typedef struct CGroupIODeviceWeight CGroupIODeviceWeight;
typedef struct CGroupRuntime CGroupRuntime;
typedef struct CGroupSocketBindItem CGroupSocketBindItem;
typedef struct DynamicCreds DynamicCreds;
typedef struct DynamicUser DynamicUser;
typedef struct ExecCommand ExecCommand;
typedef struct ExecContext ExecContext;
typedef struct ExecParameters ExecParameters;
typedef struct ExecRuntime ExecRuntime;
typedef struct ExecSharedRuntime ExecSharedRuntime;
typedef struct Job Job;
typedef struct JobDependency JobDependency;
typedef struct KillContext KillContext;
typedef struct Manager Manager;
typedef struct MountImage MountImage;
typedef struct PathSpec PathSpec;
typedef struct Scope Scope;
typedef struct Service Service;
typedef struct Socket Socket;
typedef struct SocketPeer SocketPeer;
typedef struct TemporaryFileSystem TemporaryFileSystem;
typedef struct Unit Unit;
typedef struct UnitRef UnitRef;

struct restrict_fs_bpf;
