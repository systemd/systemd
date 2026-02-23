/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "varlink-util.h"

typedef struct GetEntriesParameters {
        char **units;
        char **user_units;
        const char *namespace;
        uid_t uid;
        int priority;
        uint64_t limit;
} GetEntriesParameters;

static void get_entries_parameters_done(GetEntriesParameters *p) {
        assert(p);

        p->units = strv_free(p->units);
        p->user_units = strv_free(p->user_units);
}

int vl_method_get_entries(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "units",     SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,         offsetof(GetEntriesParameters, units),      0 },
                { "uid",       _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,      offsetof(GetEntriesParameters, uid),        0 },
                { "userUnits", SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,         offsetof(GetEntriesParameters, user_units), 0 },
                { "namespace", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(GetEntriesParameters, namespace),  0 },
                { "priority",  _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_log_level,       offsetof(GetEntriesParameters, priority),   0 },
                { "limit",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(GetEntriesParameters, limit),      0 },
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
        r = sd_journal_open_namespace(&j, p.namespace, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE);
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

        r = varlink_set_sentinel(link, "io.systemd.JournalAccess.NoEntries");
        if (r < 0)
                return r;

        for (uint64_t i = 0; i < n; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;

                r = sd_journal_next(j);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = journal_entry_to_json(j, OUTPUT_SHOW_ALL, /* output_fields= */ NULL, &entry);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue; /* skip corrupted entry */

                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("entry", entry));
                if (r < 0)
                        return r;
        }

        return 0;
}
