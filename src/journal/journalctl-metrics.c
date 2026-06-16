/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-journal.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "escape.h"
#include "journal-internal.h"
#include "journalctl-metrics.h"
#include "json-util.h"
#include "log.h"
#include "memory-util.h"
#include "metrics.h"
#include "stdio-util.h"
#include "string-util.h"
#include "utf8.h"

#define N_RECENT_HIGH_PRIORITY 10

/* TODO: similar to e.g. bsod.c:110, should we add a shared helper for it? */
static int get_field(sd_journal *j, const char *field_name, char **ret) {
        const void *data;
        size_t data_len, prefix_len;
        int r;

        assert(j);
        assert(field_name);
        assert(ret);

        r = sd_journal_get_data(j, field_name, &data, &data_len);
        if (r == -ENOENT) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        prefix_len = strlen(field_name) + 1;  /* FIELD_NAME= */
        /* data is always "FIELD_NAME=value" so this assert must hold */
        assert(data_len >= prefix_len);

        const char *value = (const char*) data + prefix_len;
        size_t value_len = data_len - prefix_len;

        /* Journal entries might contain \0 or non utf-8 data so escape as needed */
        char *s = utf8_is_printable(value, value_len) ?
                memdup_suffix0(value, value_len) :
                cescape_length(value, value_len);
        if (!s)
                return log_oom();

        *ret = s;
        return 1;
}

static int recent_high_priority_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(mf && mf->name);
        assert(link);

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_SYSTEM | SD_JOURNAL_ASSUME_IMMUTABLE);
        if (r < 0)
                return log_debug_errno(r, "Failed to open journal, ignoring: %m");

        for (int i = 0; i <= LOG_ERR; i++) {
                r = journal_add_matchf(j, "PRIORITY=%d", i);
                if (r < 0)
                        return r;
        }
        r = sd_journal_add_conjunction(j);
        if (r < 0)
                return r;

        r = sd_journal_seek_tail(j);
        if (r < 0)
                return r;

        /* Walk backwards from the tail so we get the most recent matches first, capped at N. */
        for (unsigned n = 0; n < N_RECENT_HIGH_PRIORITY; n++) {
                _cleanup_free_ char *message = NULL, *ident = NULL, *priority = NULL, *pid = NULL,
                        *unit = NULL, *comm = NULL, *boot_id = NULL, *uid = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                char realtime_str[DECIMAL_STR_MAX(uint64_t)] = "";
                uint64_t realtime;

                r = sd_journal_previous(j);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* XXX: or should we use something like journal_entry_to_json and sent the full entry? */
                r = get_field(j, "MESSAGE", &message);
                if (r < 0) {
                        log_debug_errno(r, "Failed to read MESSAGE field, skipping entry: %m");
                        continue;
                }
                if (!message)
                        continue; /* nothing to report without a message */

                (void) get_field(j, "SYSLOG_IDENTIFIER", &ident);
                (void) get_field(j, "PRIORITY", &priority);
                (void) get_field(j, "_PID", &pid);
                (void) get_field(j, "_UID", &uid);
                (void) get_field(j, "_COMM", &comm);
                (void) get_field(j, "_SYSTEMD_UNIT", &unit);
                (void) get_field(j, "_BOOT_ID", &boot_id);

                if (sd_journal_get_realtime_usec(j, &realtime) >= 0)
                        xsprintf(realtime_str, "%" PRIu64, realtime);

                r = sd_json_buildo(
                                &fields,
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("priority", priority),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("realtimeUSec", realtime_str),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("unit", unit),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("comm", comm),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("pid", pid),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("uid", uid),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("bootId", boot_id));
                if (r < 0)
                        return r;

                r = metric_build_send_string(mf, link, /* object= */ ident, message, fields);
                if (r < 0)
                        log_debug_errno(r, "Failed to send journal metric, skipping entry: %m");
        }

        return 0;
}

static const MetricFamily journal_metric_family_table[] = {
        {
                /* XXX: or just io.systemd.Journal.HighPriority */
                .name = "io.systemd.Journal.HighPriorityMessage",
                .description = "The 10 most recent high-priority (emerg/alert/crit/err) journal messages.",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = recent_high_priority_generate,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(journal_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(journal_metric_family_table, link, parameters, flags, userdata);
}
