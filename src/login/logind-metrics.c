/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "log.h"
#include "logind.h"
#include "logind-counters.h"
#include "logind-metrics.h"
#include "logind-session.h"
#include "metrics.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "virt.h"

#define METRIC_IO_SYSTEMD_LOGIN_PREFIX "io.systemd.Login."

static int send_per_class(const MetricFamily *mf, sd_varlink *link, SessionClass class, uint64_t value) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
        int r;

        r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("class", session_class_to_string(class)));
        if (r < 0)
                return r;

        return metric_build_send_unsigned(mf, link, /* object= */ NULL, value, fields);
}

static int current_sessions_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        uint64_t n[_SESSION_CLASS_MAX] = {};
        Session *s;
        int r;

        assert(mf);
        assert(link);

        /* Sessions in closing state are included */
        HASHMAP_FOREACH(s, m->sessions)
                if (s->started && s->class >= 0)
                        n[s->class]++;

        for (SessionClass c = 0; c < _SESSION_CLASS_MAX; c++) {
                if (c == SESSION_NONE)
                        continue;

                r = send_per_class(mf, link, c, n[c]);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int sessions_started_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(mf);
        assert(link);

        if (!m->counters)
                return 0;

        for (SessionClass c = 0; c < _SESSION_CLASS_MAX; c++) {
                if (c == SESSION_NONE)
                        continue;

                r = send_per_class(mf, link, c, m->counters->n_sessions_started[c]);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int suspend_counter_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        int r;

        assert(mf);
        assert(link);

        if (detect_container() > 0)
                return 0;

        FOREACH_STRING(result, "success", "fail") {
                _cleanup_free_ char *p = NULL, *s = NULL;
                uint64_t v;

                p = strjoin("/sys/power/suspend_stats/", result);
                if (!p)
                        return -ENOMEM;

                r = read_one_line_file(p, &s);
                if (r == -ENOENT) {
                        log_debug_errno(r, "%s does not exist, not reporting suspend counters.", p);
                        return 0;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", p);

                r = safe_atou64(s, &v);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse %s: %m", p);

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("result", result));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(mf, link, /* object= */ NULL, v, fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const MetricFamily login_metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
                .name = METRIC_IO_SYSTEMD_LOGIN_PREFIX "CurrentSessions",
                .description = "Number of current sessions, including closing ones, by session class",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = current_sessions_generate,
        },
        {
                .name = METRIC_IO_SYSTEMD_LOGIN_PREFIX "SessionsStarted",
                .description = "Number of sessions started since boot, by session class",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = sessions_started_generate,
        },
        {
                .name = METRIC_IO_SYSTEMD_LOGIN_PREFIX "SuspendCounter",
                .description = "Number of suspend cycles since boot, by result (result=success|fail)",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = suspend_counter_generate,
        },
        {}
};

static int vl_method_metrics_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(login_metric_family_table, link, parameters, flags, userdata);
}

static int vl_method_metrics_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(login_metric_family_table, link, parameters, flags, userdata);
}

int manager_metrics_init(Manager *m, int fd) {
        _unused_ _cleanup_close_ int fd_close = fd; /* take possession */
        int r;

        assert(m);

        if (m->metrics_varlink_server)
                return 0;

        if (fd < 0 && invoked_by_systemd()) {
                log_debug("systemd-logind-metrics.socket seems to be disabled, not installing metrics varlink server.");
                return 0;
        }

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        r = metrics_setup_varlink_server(
                        &s,
                        SD_VARLINK_SERVER_INHERIT_USERDATA,
                        m->event,
                        SD_EVENT_PRIORITY_NORMAL,
                        vl_method_metrics_list,
                        vl_method_metrics_describe,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to set up metrics varlink server: %m");

        if (fd < 0) {
                r = sd_varlink_server_listen_address(
                                s,
                                "/run/systemd/report/io.systemd.Login",
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

void manager_metrics_done(Manager *m) {
        assert(m);

        m->metrics_varlink_server = sd_varlink_server_unref(m->metrics_varlink_server);
}
