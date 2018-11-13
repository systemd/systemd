/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <string.h>

#include "alloc-util.h"
#include "fileio.h"
#include "log.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "udev-util.h"
#include "udev.h"

static const char* const resolve_name_timing_table[_RESOLVE_NAME_TIMING_MAX] = {
        [RESOLVE_NAME_NEVER] = "never",
        [RESOLVE_NAME_LATE] = "late",
        [RESOLVE_NAME_EARLY] = "early",
};

DEFINE_STRING_TABLE_LOOKUP(resolve_name_timing, ResolveNameTiming);

int udev_parse_config_full(
                unsigned *ret_children_max,
                usec_t *ret_exec_delay_usec,
                usec_t *ret_event_timeout_usec) {

        _cleanup_free_ char *log_val = NULL, *children_max = NULL, *exec_delay = NULL, *event_timeout = NULL;
        int r;

        r = parse_env_file(NULL, "/etc/udev/udev.conf", NEWLINE,
                           "udev_log", &log_val,
                           "children_max", &children_max,
                           "exec_delay", &exec_delay,
                           "event_timeout", &event_timeout,
                           NULL);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        if (log_val) {
                const char *log;
                size_t n;

                /* unquote */
                n = strlen(log_val);
                if (n >= 2 &&
                    ((log_val[0] == '"' && log_val[n-1] == '"') ||
                     (log_val[0] == '\'' && log_val[n-1] == '\''))) {
                        log_val[n - 1] = '\0';
                        log = log_val + 1;
                } else
                        log = log_val;

                /* we set the udev log level here explicitly, this is supposed
                 * to regulate the code in libudev/ and udev/. */
                r = log_set_max_level_from_string_realm(LOG_REALM_UDEV, log);
                if (r < 0)
                        log_debug_errno(r, "/etc/udev/udev.conf: failed to set udev log level '%s', ignoring: %m", log);
        }

        if (ret_children_max && children_max) {
                r = safe_atou(children_max, ret_children_max);
                if (r < 0)
                        log_notice_errno(r, "/etc/udev/udev.conf: failed to set parse children_max=%s, ignoring: %m", children_max);
        }

        if (ret_exec_delay_usec && exec_delay) {
                r = parse_sec(exec_delay, ret_exec_delay_usec);
                if (r < 0)
                        log_notice_errno(r, "/etc/udev/udev.conf: failed to set parse exec_delay=%s, ignoring: %m", exec_delay);
        }

        if (ret_event_timeout_usec && event_timeout) {
                r = parse_sec(event_timeout, ret_event_timeout_usec);
                if (r < 0)
                        log_notice_errno(r, "/etc/udev/udev.conf: failed to set parse event_timeout=%s, ignoring: %m", event_timeout);
        }

        return 0;
}
