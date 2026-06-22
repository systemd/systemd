/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-journal.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "journalctl.h"
#include "journalctl-filter.h"
#include "journalctl-metrics.h"
#include "log.h"
#include "logs-show.h"
#include "metrics.h"
#include "output-mode.h"

/* Fallback cap so we never stream unbounded entries when --lines= is "all" or unset. */
#define N_RECENT_HIGH_PRIORITY 10

/* Set a maximum scan factor to avoid unbound iterating through the journal */
#define RECENT_HIGH_PRIORITY_SCAN_FACTOR 50

static int recent_high_priority_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(mf && mf->name);
        assert(link);

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_SYSTEM | SD_JOURNAL_ASSUME_IMMUTABLE);
        if (r < 0)
                return log_debug_errno(r, "Failed to open journal, ignoring: %m");

        /* Get filters (--priority=, units, matches, ...) from the command-line. */
        r = add_filters(j, /* matches= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to add journal filters: %m");

        r = sd_journal_seek_tail(j);
        if (r < 0)
                return log_debug_errno(r, "Failed to seek to journal tail: %m");

        /* The --lines=+N argument does not make much sense for a metrics provider so we ignore it here. */
        if (arg_lines_oldest)
                log_warning("--lines=+N is not supported when serving the metrics interface, ignoring.");

        uint64_t max_lines = arg_lines_needs_seek_end() ? (uint64_t) arg_lines : N_RECENT_HIGH_PRIORITY;
        uint64_t max_scan = max_lines * RECENT_HIGH_PRIORITY_SCAN_FACTOR;

        for (uint64_t found = 0, scanned = 0; found < max_lines && scanned < max_scan; scanned++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;

                r = sd_journal_previous(j);
                if (r < 0)
                        return log_debug_errno(r, "Failed to iterate to previous journal entry: %m");
                if (r == 0)
                        break;

                r = journal_entry_to_json(j, OUTPUT_SHOW_ALL, /* output_fields= */ NULL, &entry);
                if (r < 0) {
                        log_debug_errno(r, "Failed to convert journal entry to JSON, skipping entry: %m");
                        continue;
                }
                if (r == 0 || !entry)
                        continue;

                const char *message = sd_json_variant_string(sd_json_variant_by_key(entry, "MESSAGE"));
                if (!message)
                        continue; /* skip entries whose MESSAGE is absent or non-printable */

                const char *ident = sd_json_variant_string(sd_json_variant_by_key(entry, "SYSLOG_IDENTIFIER"));

                r = metric_build_send_object(mf, link, /* object= */ ident, entry, /* fields= */ NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to send journal metric: %m");

                found++;
        }

        return 0;
}

static const MetricFamily journal_metric_family_table[] = {
        {
                .name = METRIC_IO_SYSTEMD_JOURNAL_PREFIX "HighPriorityMessage",
                .description = "The most recent high-priority journal messages",
                .type = METRIC_FAMILY_TYPE_JSON_OBJECT,
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
