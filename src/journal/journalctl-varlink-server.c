/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <grp.h>
#include <unistd.h>

#include "sd-journal.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "format-util.h"
#include "journal-internal.h"
#include "journalctl-util.h"
#include "journalctl-varlink-server.h"
#include "log.h"
#include "logs-show.h"
#include "output-mode.h"
#include "strv.h"
#include "user-util.h"
#include "varlink-util.h"

typedef struct GetEntriesParameters {
        char **units;
        char **user_units;
        char *namespace;
        int64_t priority;
        uint64_t limit;
} GetEntriesParameters;

static void get_entries_parameters_done(GetEntriesParameters *p) {
        assert(p);
        p->units = strv_free(p->units);
        p->user_units = strv_free(p->user_units);
        p->namespace = mfree(p->namespace);
}

int vl_method_get_entries(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "units",     SD_JSON_VARIANT_ARRAY,          sd_json_dispatch_strv,   offsetof(GetEntriesParameters, units),      0 },
                { "userUnits", SD_JSON_VARIANT_ARRAY,          sd_json_dispatch_strv,   offsetof(GetEntriesParameters, user_units), 0 },
                { "namespace", SD_JSON_VARIANT_STRING,          sd_json_dispatch_string, offsetof(GetEntriesParameters, namespace),  0 },
                { "priority",  _SD_JSON_VARIANT_TYPE_INVALID,  sd_json_dispatch_int64,  offsetof(GetEntriesParameters, priority),   0 },
                { "limit",     _SD_JSON_VARIANT_TYPE_INVALID,  sd_json_dispatch_uint64, offsetof(GetEntriesParameters, limit),      0 },
                {}
        };

        _cleanup_(get_entries_parameters_done) GetEntriesParameters p = {
                .priority = -1,
        };
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        /* drop privileges to the peer's identity so we can just rely on journal file ACLs. This is okay
         * because Accept=yes gives us a fresh process per connection. */
        if (getuid() == 0) {
                uid_t peer_uid;

                r = sd_varlink_get_peer_uid(link, &peer_uid);
                if (r < 0)
                        return log_error_errno(r, "Failed to get peer UID: %m");

                if (peer_uid != 0) {
                        _cleanup_free_ struct passwd *pw = NULL;
                        _cleanup_free_ gid_t *gids = NULL;
                        int ngroups;

                        r = getpwuid_malloc(peer_uid, &pw);
                        if (r < 0)
                                return log_error_errno(r, "Failed to resolve peer UID " UID_FMT ": %m", peer_uid);

                        errno = 0;
                        ngroups = (int) sysconf(_SC_NGROUPS_MAX);
                        if (ngroups < 0)
                                return log_error_errno(errno_or_else(EOPNOTSUPP), "Failed to determine NGROUPS_MAX: %m");

                        gids = new(gid_t, ngroups);
                        if (!gids)
                                return log_oom();

                        if (getgrouplist(pw->pw_name, pw->pw_gid, gids, &ngroups) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get supplementary group list: %m");

                        r = fully_set_uid_gid(peer_uid, pw->pw_gid, gids, ngroups);
                        if (r < 0)
                                return log_error_errno(r, "Failed to drop privileges: %m");
                }
        }

        r = sd_journal_open_namespace(&j, p.namespace, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal: %m");

        r = journal_add_unit_matches(j, MATCH_UNIT_ALL, /* mangle_flags= */ 0, p.units, p.user_units);
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

        /* this simulates "journalctl -n $p.limit" */
        r = sd_journal_seek_tail(j);
        if (r < 0)
                return log_error_errno(r, "Failed to seek to tail: %m");

        if (p.limit > 10000)
                return sd_varlink_error_invalid_parameter_name(link, "limit");

        uint64_t n = p.limit == 0 ? 100 : p.limit;

        r = varlink_set_sentinel(link, "io.systemd.Journalctl.NoEntries");
        if (r < 0)
                return r;

        for (uint64_t i = 0; i < n; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;

                r = sd_journal_previous(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to iterate journal: %m");
                if (r == 0)
                        break;

                r = journal_entry_to_json(j, OUTPUT_SHOW_ALL, /* output_fields= */ NULL, &entry);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue; /* skip corrupted entry */

                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR("entry", SD_JSON_BUILD_VARIANT(entry)));
                if (r < 0)
                        return r;
        }

        return 0;
}
