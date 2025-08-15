/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>

#include "log.h"
#include "nss-util.h"

static void log_setup_nss_internal(void) {
        log_set_assert_return_is_critical_from_env();
        log_parse_environment_variables();
}

void log_setup_nss(void (*setup)(void)) {
        static pthread_once_t once = PTHREAD_ONCE_INIT;
        assert_se(pthread_once(&once, setup ?: log_setup_nss_internal) == 0);
}
