/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct SyncReq SyncReq;
typedef struct StreamSyncReq StreamSyncReq;

#include "journald-server.h"
#include "macro.h"

/* Encapsulates the synchronization request data we need to keep per STDOUT stream. Primarily a byte counter
 * to count down. */
struct StreamSyncReq {
        SyncReq *req;
        StdoutStream *stream;

        uint64_t pending_siocinq; /* The SIOCINQ counter when the sync was initiated */

        LIST_FIELDS(StreamSyncReq, by_sync_req);
        LIST_FIELDS(StreamSyncReq, by_stdout_stream);
};

/* Encapsulates a synchronization request */
struct SyncReq {
        Server *server;
        sd_varlink *link;

        bool offline; /* if true, we'll offline the journal files after sync is complete */

        usec_t timestamp; /* CLOCK_REALTIME timestamp when synchronization request was initiated */
        sd_event_source *idle_event_source;

        LIST_HEAD(StreamSyncReq, stream_sync_reqs);

        unsigned prioq_idx;
};

StreamSyncReq *stream_sync_req_free(StreamSyncReq *ssr);
DEFINE_TRIVIAL_CLEANUP_FUNC(StreamSyncReq*, stream_sync_req_free);
void stream_sync_req_advance(StreamSyncReq *ssr, size_t p);

int sync_req_new(Server *s, sd_varlink *link, SyncReq **ret);
SyncReq* sync_req_free(SyncReq *req);
DEFINE_TRIVIAL_CLEANUP_FUNC(SyncReq*, sync_req_free);

bool sync_req_revalidate(SyncReq *req);
void sync_req_revalidate_by_timestamp(Server *s);
