/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h" // IWYU pragma: export

typedef enum CGroupDevicePolicy CGroupDevicePolicy;
typedef enum CGroupDevicePermissions CGroupDevicePermissions;
typedef enum CGroupMask CGroupMask;
typedef enum ExecPreserveMode ExecPreserveMode;
typedef enum JobResult JobResult;
typedef enum JobState JobState;
typedef enum JobType JobType;
typedef enum TransactionAddFlags TransactionAddFlags;
typedef enum UnitDependencyAtom UnitDependencyAtom;
typedef enum UnitWriteFlags UnitWriteFlags;

typedef struct ActivationDetails ActivationDetails;
typedef struct BindMount BindMount;
typedef struct CGroupContext CGroupContext;
typedef struct CGroupRuntime CGroupRuntime;
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
typedef struct Scope Scope;
typedef struct Socket Socket;
typedef struct SocketPeer SocketPeer;
typedef struct TemporaryFileSystem TemporaryFileSystem;
typedef struct Unit Unit;

struct restrict_fs_bpf;
