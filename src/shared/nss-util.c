/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <stdlib.h>

#include "sd-json.h"

#include "assert-util.h"
#include "log.h"
#include "log-assert-critical.h"
#include "nss-util.h"

sd_json_dispatch_flags_t nss_json_dispatch_flags = SD_JSON_ALLOW_EXTENSIONS;

static void log_setup_nss_internal(void) {
        int r;

        log_set_assert_return_is_critical_from_env();
        log_parse_environment_variables();

        const char *e = getenv("SYSTEMD_NSS_LOG_LEVEL");
        if (e) {
                /* NSS plugins are linked statically to all of our own libraries so this will only override
                 * the log level for the NSS plugin, and not for the entire systemd binary, since each will
                 * have their own log_level TLS variable. */
                r = log_set_max_level_from_string(e);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse NSS log level '%s', ignoring: %m", e);
        }

        if (DEBUG_LOGGING)
                nss_json_dispatch_flags = SD_JSON_LOG;
}

void log_setup_nss(void) {
        static pthread_once_t once = PTHREAD_ONCE_INIT;
        assert_se(pthread_once(&once, log_setup_nss_internal) == 0);
}
