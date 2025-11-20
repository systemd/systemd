/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/sockios.h>
#include <poll.h>
#include <sys/ioctl.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "io-util.h"
#include "journald-manager.h"
#include "journald-stream.h"
#include "journald-sync.h"
#include "journald-varlink.h"
#include "log.h"
#include "prioq.h"
#include "socket-netlink.h"
#include "time-util.h"

StreamSyncReq *stream_sync_req_free(StreamSyncReq *ssr) {
        if (!ssr)
                return NULL;

        if (ssr->req)
                LIST_REMOVE(by_sync_req, ssr->req->stream_sync_reqs, ssr);
        if (ssr->stream)
                LIST_REMOVE(by_stdout_stream, ssr->stream->stream_sync_reqs, ssr);

        return mfree(ssr);
}

void stream_sync_req_advance_revalidate(StreamSyncReq *ssr, size_t p) {
        assert(ssr);

        /* Subtract the specified number of bytes from the byte counter. And when we hit zero we consider
         * this stream processed for the synchronization request */

        /* NB: This might invalidate the 'ssr' object! */

        if (p < ssr->pending_siocinq) {
                ssr->pending_siocinq -= p;
                return;
        }

        SyncReq *req = ASSERT_PTR(ssr->req);
        stream_sync_req_free(TAKE_PTR(ssr));

        /* Maybe we are done now? */
        sync_req_revalidate(TAKE_PTR(req));
}

static bool sync_req_is_complete(SyncReq *req) {
        int r;

        assert(req);
        assert(req->manager);

        /* In case the clock jumped backwards, let's adjust the timestamp, to guarantee reasonably quick
         * termination */
        usec_t n = now(CLOCK_REALTIME);
        if (n < req->realtime)
                req->realtime = n;

        if (req->realtime_prioq_idx != PRIOQ_IDX_NULL) {
                /* If this sync request is still in the priority queue it means we still need to check if
                 * incoming message timestamps are now newer than then sync request timestamp. */

                if (req->manager->native_fd >= 0 &&
                    req->manager->native_timestamp < req->realtime) {
                        r = fd_wait_for_event(req->manager->native_fd, POLLIN, /* timeout= */ 0);
                        if (r < 0)
                                log_debug_errno(r, "Failed to determine pending IO events of native socket, ignoring: %m");
                        else if (r != 0) /* if there's more queued we need to wait for the timestamp to pass. If it's idle though we are done here. */
                                return false;
                }

                if (req->manager->syslog_fd >= 0&&
                    req->manager->syslog_timestamp < req->realtime) {
                        r = fd_wait_for_event(req->manager->syslog_fd, POLLIN, /* timeout= */ 0);
                        if (r < 0)
                                log_debug_errno(r, "Failed to determine pending IO events of syslog socket, ignoring: %m");
                        else if (r != 0)
                                return false;
                }

                /* This sync request is fulfilled for the native + syslog datagram streams? Then, let's
                 * remove this sync request from the priority queue, so that we dont need to consider it
                 * anymore. */
                assert(prioq_remove(req->manager->sync_req_realtime_prioq, req, &req->realtime_prioq_idx) > 0);
        }

        if (req->boottime_prioq_idx != PRIOQ_IDX_NULL) {
                /* Very similar to the above, but for /dev/kmsg we operate on the CLOCK_BOOTTIME clock */

                if (req->manager->dev_kmsg_fd >= 0 &&
                    req->manager->dev_kmsg_timestamp < req->boottime) {
                        r = fd_wait_for_event(req->manager->dev_kmsg_fd, POLLIN, /* timeout= */ 0);
                        if (r < 0)
                                log_debug_errno(r, "Failed to determine pending IO events of /dev/kmsg file descriptor, ignoring: %m");
                        else if (r != 0)
                                return false;
                }

                assert(prioq_remove(req->manager->sync_req_boottime_prioq, req, &req->boottime_prioq_idx) > 0);
        }

        /* If there are still streams with pending counters, we still need to look into things */
        if (req->stream_sync_reqs)
                return false;

        /* If there are still pending connections from before the sync started, we still need to look into things */
        if (req->pending_rqlen > 0)
                return false;

        return true;
}

static int on_idle(sd_event_source *s, void *userdata) {
        SyncReq *req = ASSERT_PTR(userdata);

        req->idle_event_source = sd_event_source_disable_unref(req->idle_event_source);

        /* When this idle event triggers, then we definitely are done with the synchronization request. This
         * is a safety net of a kind, to ensure we'll definitely put an end to any synchronization request,
         * even if we are confused by CLOCK_REALTIME jumps or similar. */
        sync_req_varlink_reply(TAKE_PTR(req));
        return 0;
}

SyncReq* sync_req_free(SyncReq *req) {
        if (!req)
                return NULL;

        if (req->manager) {
                if (req->realtime_prioq_idx != PRIOQ_IDX_NULL)
                        assert_se(prioq_remove(req->manager->sync_req_realtime_prioq, req, &req->realtime_prioq_idx) > 0);

                if (req->boottime_prioq_idx != PRIOQ_IDX_NULL)
                        assert_se(prioq_remove(req->manager->sync_req_boottime_prioq, req, &req->boottime_prioq_idx) > 0);

                if (req->pending_rqlen > 0)
                        LIST_REMOVE(pending_rqlen, req->manager->sync_req_pending_rqlen, req);
        }

        sd_event_source_disable_unref(req->idle_event_source);

        sd_varlink_unref(req->link);

        while (req->stream_sync_reqs)
                stream_sync_req_free(req->stream_sync_reqs);

        return mfree(req);
}

static int sync_req_realtime_compare(const SyncReq *x, const SyncReq *y) {
        return CMP(ASSERT_PTR(x)->realtime, ASSERT_PTR(y)->realtime);
}

static int sync_req_boottime_compare(const SyncReq *x, const SyncReq *y) {
        return CMP(ASSERT_PTR(x)->boottime, ASSERT_PTR(y)->boottime);
}

static int sync_req_add_stream(SyncReq *req, StdoutStream *ss) {
        assert(req);
        assert(ss);

        int v = 0;
        if (ioctl(ss->fd, SIOCINQ, &v) < 0)
                log_debug_errno(errno, "Failed to issue SIOCINQ on stream socket, ignoring: %m");
        if (v <= 0)
                return 0; /* Pending messages are zero anyway? then there's nothing to track */

        _cleanup_(stream_sync_req_freep) StreamSyncReq *ssr = new(StreamSyncReq, 1);
        if (!ssr)
                return -ENOMEM;

        *ssr = (StreamSyncReq) {
                .stream = ss,
                .pending_siocinq = v,
                .req = req,
        };

        LIST_PREPEND(by_sync_req, req->stream_sync_reqs, ssr);
        LIST_PREPEND(by_stdout_stream, ss->stream_sync_reqs, ssr);

        TAKE_PTR(ssr);
        return 1;
}

int sync_req_new(Manager *m, sd_varlink *link, SyncReq **ret) {
        int r;

        assert(m);
        assert(link);
        assert(ret);

        _cleanup_(sync_req_freep) SyncReq *req = new(SyncReq, 1);
        if (!req)
                return -ENOMEM;

        *req = (SyncReq) {
                .manager = m,
                .link = sd_varlink_ref(link),
                .realtime_prioq_idx = PRIOQ_IDX_NULL,
                .boottime_prioq_idx = PRIOQ_IDX_NULL,
        };

        /* We use five distinct mechanisms to determine when the synchronization request is complete:
         *
         * 1. For the syslog/native AF_UNIX/SOCK_DGRAM sockets we look at the datagram timestamps: once the
         *    most recently seen datagram on the socket is newer than the timestamp when we initiated the
         *    sync request we know that all previously enqueued messages have been processed by us.
         *
         * 2. For established stream AF_UNIX/SOCK_STREAM sockets we have no timestamps. For them we take the
         *    SIOCINQ counter at the moment the synchronization request was enqueued. And once we processed
         *    the indicated number of input bytes we know that anything further was enqueued later than the
         *    original synchronization request we started from.
         *
         * 3. For pending new, un-accept()ed stream AF_UNIX/SOCK_STREAM sockets we have no timestamps either,
         *    but we can query the number of pending connections via the sockdiag netlink protocol (I so wish
         *    there was an easier, quicker way!). Once we accept()ed that many connections we know all
         *    further connections are definitely more recent than the sync request.
         *
         * 4. For /dev/kmsg we look at the log message timestamps, similar to the AF_UNIX/SOCK_DGRAM case,
         *    and they are in CLOCK_BOOTTIME clock.
         *
         * 5. Finally, as safety net we install an idle handler with a very low priority (lower than the
         *    syslog/native/stream IO handlers). If this handler is called we know that there's no pending
         *    IO, hence everything so far queued is definitely processed.
         *
         * Note the asymmetry: for AF_UNIX/SOCK_DGRAM + /dev/kmsg we go by timestamp, for established
         * AF_UNIX/SOCK_STREAM we count bytes. That's because for SOCK_STREAM we have no timestamps, and for
         * SOCK_DGRAM we have no API to query all pending bytes (as SIOCINQ on SOCK_DGRAM reports size of
         * next datagram, not size of all pending datagrams). Ideally, we'd actually use neither of this, and
         * the kernel would provide us CLOCK_MONOTONIC timestamps...
         *
         * Note that CLOCK_REALTIME is not necessarily monotonic (that's the whole point of it after all). If
         * the clock jumps then we know the algorithm will eventually terminate, because of the idle handler
         * that is our safety net. (Also, whenever we see poll() return an empty revents for some source we
         * know everything is processed by now regardless of any timestamps or pending byte or connection
         * counts.) */

        req->realtime = now(CLOCK_REALTIME);
        req->boottime = now(CLOCK_BOOTTIME);

        if (m->native_event_source || m->syslog_event_source) {
                r = prioq_ensure_put(&m->sync_req_realtime_prioq, sync_req_realtime_compare, req, &req->realtime_prioq_idx);
                if (r < 0)
                        return r;
        }

        if (m->dev_kmsg_event_source) {
                r = prioq_ensure_put(&m->sync_req_boottime_prioq, sync_req_boottime_compare, req, &req->boottime_prioq_idx);
                if (r < 0)
                        return r;
        }

        r = sd_event_add_defer(m->event, &req->idle_event_source, on_idle, req);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(req->idle_event_source, SD_EVENT_PRIORITY_NORMAL+15);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(req->idle_event_source, "deferred-sync");

        /* Now determine the pending byte counter for each stdout stream. If non-zero allocate a
         * StreamSyncReq for the stream to keep track of it */
        LIST_FOREACH(stdout_stream, ss, m->stdout_streams) {
                r = sync_req_add_stream(req, ss);
                if (r < 0)
                        return r;
        }

        /* Also track how many pending, incoming stream sockets there are currently, so that we process them
         * too */
        r = af_unix_get_qlen(m->stdout_fd, &req->pending_rqlen);
        if (r < 0)
                log_warning_errno(r, "Failed to determine current incoming queue length, ignoring: %m");
        if (req->pending_rqlen > 0)
                LIST_PREPEND(pending_rqlen, m->sync_req_pending_rqlen, req);

        *ret = TAKE_PTR(req);
        return 0;
}

static void sync_req_advance_rqlen_revalidate(SyncReq *req, uint32_t current_rqlen, StdoutStream *ss) {
        int r;

        assert(req);

        /* Invoked whenever a new connection was accept()ed, i.e. dropped off the queue of pending incoming
         * connections. We decrease the qlen counter by one here, except if the new overall counter is
         * already below our target. */

        uint32_t n;
        if (req->pending_rqlen <= 0)
                n = 0;
        else if (req->pending_rqlen > current_rqlen)
                n = current_rqlen;
        else
                n = req->pending_rqlen - 1;

        if (req->pending_rqlen > 0) {
                /* if this synchronization request is supposed to process a non-zero number of connections we
                 * need to also track what's inside those stream connections */
                if (ss) {
                        r = sync_req_add_stream(req, ss);
                        if (r < 0)
                                log_warning_errno(r, "Failed to track stream queue size, ignoring: %m");
                }

                /* If there are no more connections to wait for, remove us from the list of synchronization
                 * requests with non-zero pending connection counters */
                if (n == 0)
                        LIST_REMOVE(pending_rqlen, req->manager->sync_req_pending_rqlen, req);
        }

        req->pending_rqlen = n;

        sync_req_revalidate(req);
}

void manager_notify_stream(Manager *m, StdoutStream *stream) {
        int r;

        assert(m);

        /* Invoked whenever a new connection was accept()ed, i.e. dropped off the queue of pending incoming
         * connections. */

        if (!m->sync_req_pending_rqlen)
                return;

        uint32_t current_qlen;

        r = af_unix_get_qlen(m->stdout_fd, &current_qlen);
        if (r < 0) {
                log_warning_errno(r, "Failed to determine current AF_UNIX stream socket pending connections, ignoring: %m");
                current_qlen = UINT32_MAX;
        }

        LIST_FOREACH(pending_rqlen, sr, m->sync_req_pending_rqlen)
                /* NB: this might invalidate the SyncReq object! */
                sync_req_advance_rqlen_revalidate(sr, current_qlen, stream);
}

bool sync_req_revalidate(SyncReq *req) {
        assert(req);

        /* Check if the synchronization request is complete now. If so, answer the Varlink client. NB: this
         * might invalidate the SyncReq object */

        if (!sync_req_is_complete(req))
                return false;

        sync_req_varlink_reply(TAKE_PTR(req));
        return true;
}

void sync_req_revalidate_by_timestamp(Manager *m) {
        assert(m);

        /* Go through the pending sync requests by timestamp, and complete those for which a sync is now
         * complete. */

        SyncReq *req;
        while ((req = prioq_peek(m->sync_req_realtime_prioq)))
                if (!sync_req_revalidate(req))
                        break;

        while ((req = prioq_peek(m->sync_req_boottime_prioq)))
                if (!sync_req_revalidate(req))
                        break;
}
