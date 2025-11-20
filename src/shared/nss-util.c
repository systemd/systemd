/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>

#include "sd-json.h"

#include "assert-util.h"
#include "log.h"
#include "log-assert-critical.h"
#include "nss-util.h"

sd_json_dispatch_flags_t nss_json_dispatch_flags = SD_JSON_ALLOW_EXTENSIONS;

static void log_setup_nss_internal(void) {
        log_set_assert_return_is_critical_from_env();
        log_parse_environment_variables();
        if (DEBUG_LOGGING)
                nss_json_dispatch_flags = SD_JSON_LOG;
}

void log_setup_nss(void) {
        static pthread_once_t once = PTHREAD_ONCE_INIT;
        assert_se(pthread_once(&once, log_setup_nss_internal) == 0);
}
