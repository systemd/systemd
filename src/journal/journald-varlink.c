/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-journal.h"

#include "alloc-util.h"
#include "journal-internal.h"
#include "journald-manager.h"
#include "journald-sync.h"
#include "journald-varlink.h"
#include "log.h"
#include "logs-show.h"
#include "output-mode.h"
#include "strv.h"
#include "varlink-io.systemd.Journal.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

void sync_req_varlink_reply(SyncReq *req) {
        int r;

        assert(req);

        /* This is the "second half" of the Synchronize() varlink method. This function is called when we
         * determine that no messages that were enqueued to us when the request was initiated is pending
         * anymore. */

        if (req->offline)
                manager_full_sync(req->manager, /* wait= */ true);

        log_debug("Client request to sync journal (%s offlining) completed.", req->offline ? "with" : "without");

        /* Disconnect the SyncReq from the Varlink connection object, and free it */
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = TAKE_PTR(req->link);
        sd_varlink_set_userdata(vl, req->manager); /* reinstall manager object */
        req = sync_req_free(req);

        r = sd_varlink_reply(vl, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to reply to Synchronize() client, ignoring: %m");
}

typedef struct GetEntriesParameters {
        char **units;
        char **user_units;
        int64_t priority;
        uint64_t limit;
} GetEntriesParameters;

static void get_entries_parameters_done(GetEntriesParameters *p) {
        assert(p);
        p->units = strv_free(p->units);
        p->user_units = strv_free(p->user_units);
}

typedef struct GetEntriesState {
        sd_varlink *link;          /* we ref() it */
        sd_journal *journal;       /* we TAKE_PTR() it */
        uint64_t remaining;
} GetEntriesState;

static GetEntriesState* get_entries_state_free(GetEntriesState *s) {
        if (!s)
                return NULL;

        sd_varlink_unref(s->link);
        sd_journal_close(s->journal);
        return mfree(s);
}

static void get_entries_state_destroy_callback(void *userdata) {
        get_entries_state_free(userdata);
}

/* This is arbitrary, we just need a balance between yielding too often and becoming unresponsive */
#define GET_ENTRIES_BATCH_SIZE 128

static int on_get_entries_defer(sd_event_source *s, void *userdata) {
        GetEntriesState *state = ASSERT_PTR(userdata);
        bool done = false;
        int r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *previous = NULL;
        for (uint64_t i = 0; i < GET_ENTRIES_BATCH_SIZE && state->remaining > 0; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;

                r = sd_journal_previous(state->journal);
                if (r < 0) {
                        log_error_errno(r, "Failed to iterate journal: %m");
                        goto finish;
                }
                if (r == 0) {
                        done = true;
                        break;
                }

                r = journal_entry_to_json(state->journal, OUTPUT_SHOW_ALL, /* output_fields= */ NULL, &entry);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        continue; /* ignore corrupted entry, skip without decrementing remaining */

                /* the loop always outputs the previous entry so that when we are at the end we can sent the
                 * last entry via sd_varlink_reply to indicate that the stream is finished */
                if (previous) {
                        r = sd_varlink_notify(state->link, previous);
                        if (r < 0)
                                goto finish;
                        previous = sd_json_variant_unref(previous);
                }

                r = sd_json_buildo(
                                &previous,
                                SD_JSON_BUILD_PAIR("entry", SD_JSON_BUILD_VARIANT(entry)));
                if (r < 0)
                        goto finish;

                state->remaining--;
        }

        if (!done && state->remaining > 0) {
                r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
                if (r < 0)
                        goto finish;
                return 0;
        }

        if (previous)
                (void) sd_varlink_reply(state->link, previous);
        else
                (void) sd_varlink_reply(state->link, NULL);

finish:
        if (r < 0)
                (void) sd_varlink_error_errno(state->link, r);
        sd_event_source_disable_unref(s);
        return 0;
}

static int vl_method_get_entries(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        /* TODO: add more filters to match what journalctl can do on the commandline */
        static const sd_json_dispatch_field dispatch_table[] = {
                { "units",            SD_JSON_VARIANT_ARRAY,   sd_json_dispatch_strv,         offsetof(GetEntriesParameters, units),              0 },
                { "userUnits",        SD_JSON_VARIANT_ARRAY,   sd_json_dispatch_strv,         offsetof(GetEntriesParameters, user_units),         0 },
                { "priority",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int64,  offsetof(GetEntriesParameters, priority),          0 },
                { "limit",            _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(GetEntriesParameters, limit),             0 },
                {}
        };

        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *es = NULL;
        _cleanup_(get_entries_parameters_done) GetEntriesParameters p = {
                .priority = -1,
        };
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        /* TODO: start extremly conservative, i.e. root only. We should allow unprivileged users to see their
         * own entries by adding a _UID= match for the peer UID eventually. And also check for membership
         * of the systemd-journal group, see access_check_var_log_journal() */
        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        if (p.limit > 10000)
                return sd_varlink_error_invalid_parameter_name(link, "limit");

        r = sd_journal_open_namespace(&j, m->namespace, SD_JOURNAL_ASSUME_IMMUTABLE);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal: %m");

        r = journal_add_unit_matches(j, MATCH_UNIT_ALL, UNIT_NAME_MANGLE_GLOB, p.units, p.user_units);
        if (r == -ENODATA)
                return sd_varlink_error(link, SD_VARLINK_ERROR_INVALID_PARAMETER, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add unit matches: %m");

        if (p.priority >= 0) {
                if (p.priority > 7)
                        return sd_varlink_error_invalid_parameter_name(link, "priority");

                for (int i = 0; i <= p.priority; i++) {
                        r = journal_add_matchf(j, "PRIORITY=%d", i);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add priority match: %m");
                }

                r = sd_journal_add_conjunction(j);
                if (r < 0)
                        return r;
        }

        r = sd_journal_seek_tail(j);
        if (r < 0)
                return log_error_errno(r, "Failed to seek to tail: %m");

        uint64_t n = p.limit == 0 ? 100 : p.limit;

        GetEntriesState *state = new(GetEntriesState, 1);
        if (!state)
                return log_oom();

        *state = (GetEntriesState) {
                .link      = sd_varlink_ref(link),
                .journal   = TAKE_PTR(j),
                .remaining = n,
        };

        r = sd_event_add_defer(m->event, &es, on_get_entries_defer, state);
        if (r < 0) {
                get_entries_state_free(state);
                return log_error_errno(r, "Failed to add defer event source: %m");
        }

        r = sd_event_source_set_priority(es, SD_EVENT_PRIORITY_NORMAL + 5);
        if (r < 0) {
                get_entries_state_free(state);
                return log_error_errno(r, "Failed to set event source priority: %m");
        }

        r = sd_event_source_set_destroy_callback(es, get_entries_state_destroy_callback);
        if (r < 0) {
                get_entries_state_free(state);
                return log_error_errno(r, "Failed to set destroy callback: %m");
        }
        (void) sd_event_source_set_description(es, "get-entries");
        /* The destroy callback is now registered on the event source, so state will be freed when the event
         * source is eventually unref'd. Prevent the _cleanup_ attribute from prematurely unreffing it. */
        es = NULL;

        return 0;
}

static int vl_method_synchronize(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int offline = -1;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "offline", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate, 0, 0},
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &offline);
        if (r != 0)
                return r;

        if (offline > 0) {
                /* Do not allow unprivileged clients to offline the journal files, since that's potentially slow */
                r = varlink_check_privileged_peer(link);
                if (r < 0)
                        return r;
        } else if (offline < 0) {
                uid_t uid = 0;

                r = sd_varlink_get_peer_uid(link, &uid);
                if (r < 0)
                        return r;

                offline = uid == 0; /* for compat, if not specified default to offlining, except for non-root */
        }

        log_full(offline ? LOG_INFO : LOG_DEBUG,
                 "Received client request to sync journal (%s offlining).", offline ? "with" : "without");

        _cleanup_(sync_req_freep) SyncReq *sr = NULL;

        r = sync_req_new(m, link, &sr);
        if (r < 0)
                return r;

        sr->offline = offline;
        sd_varlink_set_userdata(link, sr);

        sync_req_revalidate(TAKE_PTR(sr));
        return 0;
}

static int vl_method_rotate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        log_info("Received client request to rotate journal, rotating.");
        manager_full_rotate(m);
        log_debug("Client request to rotate journal completed.");

        return sd_varlink_reply(link, NULL);
}

static int vl_method_flush_to_var(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        if (m->namespace)
                return sd_varlink_error(link, "io.systemd.Journal.NotSupportedByNamespaces", NULL);

        log_info("Received client request to flush runtime journal.");
        manager_full_flush(m);
        log_debug("Client request to flush runtime journal completed.");

        return sd_varlink_reply(link, NULL);
}

static int vl_method_relinquish_var(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        if (m->namespace)
                return sd_varlink_error(link, "io.systemd.Journal.NotSupportedByNamespaces", NULL);

        log_info("Received client request to relinquish %s access.", m->system_storage.path);
        manager_relinquish_var(m);
        log_debug("Client request to relinquish %s access completed.", m->system_storage.path);

        return sd_varlink_reply(link, NULL);
}

static int vl_connect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        (void) manager_start_or_stop_idle_timer(m); /* maybe we are no longer idle */

        return 0;
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        void *u = sd_varlink_get_userdata(link);
        if (u != m) {
                /* If this is a Varlink connection that does not have the Server object as userdata, then it has a SyncReq object instead. Let's finish it. */

                SyncReq *req = u;
                sd_varlink_set_userdata(link, m); /* reinstall server object */
                sync_req_free(req);
        }

        (void) manager_start_or_stop_idle_timer(m); /* maybe we are idle now */
}

int manager_open_varlink(Manager *m, const char *socket, int fd) {
        int r;

        assert(m);

        r = varlink_server_new(
                        &m->varlink_server,
                        SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = sd_varlink_server_add_interface_many(
                        m->varlink_server,
                        &vl_interface_io_systemd_Journal,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Journal interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.Journal.GetEntries",     vl_method_get_entries,
                        "io.systemd.Journal.Synchronize",    vl_method_synchronize,
                        "io.systemd.Journal.Rotate",         vl_method_rotate,
                        "io.systemd.Journal.FlushToVar",     vl_method_flush_to_var,
                        "io.systemd.Journal.RelinquishVar",  vl_method_relinquish_var,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return r;

        r = sd_varlink_server_bind_connect(m->varlink_server, vl_connect);
        if (r < 0)
                return r;

        r = sd_varlink_server_bind_disconnect(m->varlink_server, vl_disconnect);
        if (r < 0)
                return r;

        if (fd < 0)
                r = sd_varlink_server_listen_address(m->varlink_server, socket, 0666);
        else
                r = sd_varlink_server_listen_fd(m->varlink_server, fd);
        if (r < 0)
                return r;

        r = sd_varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}
