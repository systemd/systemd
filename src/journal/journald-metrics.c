/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "journald-counters.h"
#include "journald-manager.h"
#include "journald-metrics.h"
#include "log.h"
#include "metrics.h"
#include "syslog-util.h"

#define METRIC_IO_SYSTEMD_JOURNAL_DAEMON_PREFIX "io.systemd.JournalDaemon."

static int messages_by_priority_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(mf);
        assert(link);

        if (!m->counters)
                return 0;

        for (int i = 0; i < (int) ELEMENTSOF(m->counters->n_priority); i++) {
                _cleanup_free_ char *s = NULL;
                r = log_level_to_string_alloc(i, &s);
                if (r < 0)
                        return r;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("priority", s));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(mf, link, /* object= */ NULL, m->counters->n_priority[i], fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int messages_by_transport_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(mf);
        assert(link);

        if (!m->counters)
                return 0;

        for (JournalTransport t = 0; t < _JOURNAL_TRANSPORT_MAX; t++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("transport", journal_transport_to_string(t)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(mf, link, /* object= */ NULL, m->counters->n_transport[t], fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const MetricFamily journald_metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
                .name = METRIC_IO_SYSTEMD_JOURNAL_DAEMON_PREFIX "MessagesByPriority",
                .description = "Number of log messages received since boot, by priority (priority=emerg|alert|crit|err|warning|notice|info|debug)",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = messages_by_priority_generate,
        },
        {
                .name = METRIC_IO_SYSTEMD_JOURNAL_DAEMON_PREFIX "MessagesByTransport",
                .description = "Number of log messages received since boot, by transport (transport=syslog|journal|stdout|audit|kernel)",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = messages_by_transport_generate,
        },
        {}
};

static int vl_method_metrics_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(journald_metric_family_table, link, parameters, flags, userdata);
}

static int vl_method_metrics_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(journald_metric_family_table, link, parameters, flags, userdata);
}

int manager_open_metrics(Manager *m, int fd) {
        _unused_ _cleanup_close_ int fd_close = fd; /* take possession */
        int r;

        assert(m);

        if (m->metrics_varlink_server)
                return 0;

        /* Only the main instance serves metrics for now */
        if (m->namespace)
                return 0;

        if (fd < 0 && invoked_by_systemd()) {
                log_debug("systemd-journald-metrics.socket seems to be disabled, not installing metrics varlink server.");
                return 0;
        }

        /* Process metrics requests at a lower priority than incoming log messages */
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        r = metrics_setup_varlink_server(
                        &s,
                        SD_VARLINK_SERVER_INHERIT_USERDATA,
                        m->event,
                        SD_EVENT_PRIORITY_NORMAL+10,
                        vl_method_metrics_list,
                        vl_method_metrics_describe,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to set up metrics varlink server: %m");

        if (fd < 0) {
                r = sd_varlink_server_listen_address(
                                s,
                                JOURNALD_METRICS_SOCKET,
                                0666 | SD_VARLINK_SERVER_MODE_MKDIR_0755);
                if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                        log_warning_errno(r, "Failed to bind to metrics varlink socket, ignoring: %m");
                        return 0;
                }
        } else
                r = sd_varlink_server_listen_fd(s, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to metrics varlink socket: %m");

        TAKE_FD(fd_close);
        m->metrics_varlink_server = TAKE_PTR(s);
        return 0;
}
