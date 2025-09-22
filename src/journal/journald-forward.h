/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"    /* IWYU pragma: export */
#include "forward.h"                /* IWYU pragma: export */

typedef enum Storage Storage;
typedef enum SplitMode SplitMode;
typedef enum AuditSetMode AuditSetMode;
typedef struct JournalCompressOptions JournalCompressOptions;
typedef struct JournalConfig JournalConfig;

typedef struct Manager Manager;
typedef struct StreamSyncReq StreamSyncReq;
typedef struct SyncReq SyncReq;
typedef struct ClientContext ClientContext;
typedef struct StdoutStream StdoutStream;
