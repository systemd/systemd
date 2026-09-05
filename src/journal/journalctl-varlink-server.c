/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-journal.h"
#include "sd-varlink.h"

#include "journal-internal.h"
#include "journalctl.h"
#include "journalctl-filter.h"
#include "journalctl-varlink-server.h"
#include "json-util.h"
#include "logs-show.h"
#include "output-mode.h"
#include "runtime-scope.h"
#include "strv.h"
#include "unit-name.h"          /* IWYU pragma: keep */
#include "user-util.h"

typedef struct GetEntriesParameters {
        char **units;
        char **user_units;
        const char *namespace;
        uid_t uid;
        int priority;
        uint64_t limit;
        bool follow;
} GetEntriesParameters;

static void get_entries_parameters_done(GetEntriesParameters *p) {
        assert(p);

        p->units = strv_free(p->units);
        p->user_units = strv_free(p->user_units);
}

typedef struct FollowState {
        sd_journal *journal;
        sd_varlink *link;
        sd_event_source *io_event_source;
} FollowState;

static FollowState* follow_state_free(FollowState *fs) {
        if (!fs)
                return NULL;

        sd_event_source_disable_unref(fs->io_event_source);
        sd_journal_close(fs->journal);
        sd_varlink_unref(fs->link);

        return mfree(fs);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FollowState*, follow_state_free);

void vl_on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        assert(server);
        assert(link);

        follow_state_free(sd_varlink_set_userdata(link, NULL));
}

static int entry_to_json_and_send(sd_journal *j, sd_varlink *link, bool follow) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;
        int r;

        assert(j);
        assert(link);

        r = journal_entry_to_json(j, OUTPUT_SHOW_ALL, /* output_fields= */ NULL, &entry);
        if (r <= 0)
                return r; /* 0: skip corrupted entry */

        if (follow)
                r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_VARIANT("entry", entry));
        else
                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("entry", entry));
        if (r < 0)
                return r;

        return 1;
}

static int follow_drain(FollowState *fs) {
        int r;

        assert(fs);

        for (;;) {
                r = sd_journal_next(fs->journal);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 0;

                r = entry_to_json_and_send(fs->journal, fs->link, /* follow= */ true);
                if (r < 0)
                        return r;
        }
}

static int follow_dispatch(FollowState *fs) {
        int r;

        assert(fs);

        r = sd_journal_process(fs->journal);
        if (r < 0)
                goto fail;

        if (r != SD_JOURNAL_NOP) {
                r = follow_drain(fs);
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        log_warning_errno(r, "Failed to stream journal entries, completing call: %m");

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = sd_varlink_ref(fs->link);

        /* drop our state before replying, so that the disconnect callback won't free it a second time */
        follow_state_free(sd_varlink_set_userdata(link, NULL));

        (void) sd_varlink_error_errno(link, r);

        return 0;
}

static int follow_on_journal_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        FollowState *fs = ASSERT_PTR(userdata);

        return follow_dispatch(fs);
}

static int follow_state_setup(sd_varlink *link, sd_journal *_j /* donated! */) {
        _cleanup_(sd_journal_closep) sd_journal *j = TAKE_PTR(_j); /* take possession in all cases */
        _cleanup_(follow_state_freep) FollowState *fs = NULL;
        int r;

        assert(link);
        assert(j);

        sd_varlink_server *server = ASSERT_PTR(sd_varlink_get_server(link));
        sd_event *event = ASSERT_PTR(sd_varlink_server_get_event(server));

        fs = new(FollowState, 1);
        if (!fs)
                return -ENOMEM;

        *fs = (FollowState) {
                .journal = TAKE_PTR(j),
                .link = sd_varlink_ref(link),
        };

        int fd = sd_journal_get_fd(fs->journal);
        if (fd < 0)
                return fd;

        int events = sd_journal_get_events(fs->journal);
        if (events < 0)
                return events;

        r = sd_event_add_io(event, &fs->io_event_source, fd, (uint32_t) events, follow_on_journal_io, fs);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(fs->io_event_source, "journal-follow-io");

        /* stashed on the link for vl_on_disconnect(); the link ref taken above also tells the varlink
         * dispatcher that the call is deliberately left pending */
        sd_varlink_set_userdata(link, TAKE_PTR(fs));

        return 0;
}

int vl_method_get_entries(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "units",     SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,         offsetof(GetEntriesParameters, units),      0 },
                { "uid",       _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,      offsetof(GetEntriesParameters, uid),        0 },
                { "userUnits", SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,         offsetof(GetEntriesParameters, user_units), 0 },
                { "namespace", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(GetEntriesParameters, namespace),  0 },
                { "priority",  _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_log_level,       offsetof(GetEntriesParameters, priority),   0 },
                { "limit",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(GetEntriesParameters, limit),      0 },
                { "follow",    SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,      offsetof(GetEntriesParameters, follow),     0 },
                {}
        };

        _cleanup_(get_entries_parameters_done) GetEntriesParameters p = {
                .uid = UID_INVALID,
                .priority = -1,
        };
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (arg_varlink_runtime_scope == RUNTIME_SCOPE_SYSTEM && p.user_units && !uid_is_valid(p.uid))
                return sd_varlink_error_invalid_parameter_name(link, "uid");

        /* systemd ships with sensible defaults for the system/user services and the socket permissions so we
         * do not need to do extra sd_varlink_get_peer_uid() or policykit checks here */
        r = sd_journal_open_namespace(&j, p.namespace, SD_JOURNAL_LOCAL_ONLY | (p.follow ? 0 : SD_JOURNAL_ASSUME_IMMUTABLE));
        if (r < 0)
                return r;

        r = journal_add_unit_matches(j, MATCH_UNIT_ALL, /* mangle_flags= */ 0, p.units, p.uid, p.user_units);
        if (r == -ENODATA)
                return sd_varlink_error(link, "io.systemd.JournalAccess.NoMatches", NULL);
        if (r < 0)
                return r;

        if (p.priority >= 0) {
                for (int i = 0; i <= p.priority; i++) {
                        r = journal_add_matchf(j, "PRIORITY=%d", i);
                        if (r < 0)
                                return r;
                }

                r = sd_journal_add_conjunction(j);
                if (r < 0)
                        return r;
        }

        /* create the inotify watch before draining the backlog, so entries logged in between wake us up */
        if (p.follow) {
                r = sd_journal_get_fd(j);
                if (r < 0)
                        return r;
        }

        /* this simulates "journalctl -n $p.limit" */
        r = sd_journal_seek_tail(j);
        if (r < 0)
                return r;

        /* FIXME: this restriction should be removed eventually */
        if (p.limit > 10000)
                return sd_varlink_error_invalid_parameter_name(link, "limit");

        uint64_t n = p.limit == 0 ? 100 : p.limit;

        r = sd_journal_previous_skip(j, n + 1);
        if (r < 0)
                return r;

        /* no sentinel in follow mode: an empty backlog is fine, the stream simply stays open */
        if (!p.follow) {
                r = sd_varlink_set_sentinel(link, "io.systemd.JournalAccess.NoEntries");
                if (r < 0)
                        return r;
        }

        uint64_t n_sent = 0;
        for (uint64_t i = 0; i < n; i++) {
                r = sd_journal_next(j);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = entry_to_json_and_send(j, link, p.follow);
                if (r < 0)
                        return r;

                n_sent++;
        }

        if (p.follow) {
                if (n_sent == 0) {
                        /* The backlog matched nothing, hence the journal contains no matching entry at all
                         * and anything that matches from now on is new. Seek to head like journalctl's
                         * on_first_event() does, instead of to the current realtime, which would race
                         * against entries logged while we were setting up. */
                        r = sd_journal_seek_head(j);
                        if (r < 0)
                                return r;
                }

                return follow_state_setup(link, TAKE_PTR(j));
        }

        return 0;
}
