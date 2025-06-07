/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-forward.h"
#include "list.h"

/* Encapsulates the synchronization request data we need to keep per STDOUT stream. Primarily a byte counter
 * to count down. */
typedef struct StreamSyncReq {
        SyncReq *req;
        StdoutStream *stream;

        uint64_t pending_siocinq; /* The SIOCINQ counter when the sync was initiated */

        LIST_FIELDS(StreamSyncReq, by_sync_req);
        LIST_FIELDS(StreamSyncReq, by_stdout_stream);
} StreamSyncReq;

/* Encapsulates a synchronization request */
typedef struct SyncReq {
        Manager *manager;
        sd_varlink *link;

        bool offline; /* if true, we'll offline the journal files after sync is complete */

        usec_t realtime; /* CLOCK_REALTIME timestamp when synchronization request was initiated (for syncing on AF_UNIX/SOCK_DGRAM) */
        usec_t boottime; /* CLOCK_BOOTTIME timestamp when synchronization request was initiated (for syncing on /dev/kmsg) */

        sd_event_source *idle_event_source;

        uint32_t pending_rqlen;   /* The rqlen counter on the stream AF_UNIX socket when the sync was initiated */
        LIST_FIELDS(SyncReq, pending_rqlen);

        LIST_HEAD(StreamSyncReq, stream_sync_reqs);

        unsigned realtime_prioq_idx;
        unsigned boottime_prioq_idx;
} SyncReq;

StreamSyncReq *stream_sync_req_free(StreamSyncReq *ssr);
DEFINE_TRIVIAL_CLEANUP_FUNC(StreamSyncReq*, stream_sync_req_free);
void stream_sync_req_advance_revalidate(StreamSyncReq *ssr, size_t p);

int sync_req_new(Manager *m, sd_varlink *link, SyncReq **ret);
SyncReq* sync_req_free(SyncReq *req);
DEFINE_TRIVIAL_CLEANUP_FUNC(SyncReq*, sync_req_free);

bool sync_req_revalidate(SyncReq *req);
void sync_req_revalidate_by_timestamp(Manager *m);

void manager_notify_stream(Manager *m, StdoutStream *stream);
