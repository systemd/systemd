/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>

#include "assert-util.h"
#include "errno-util.h"
#include "log.h"

static bool assert_return_is_critical = BUILD_MODE_DEVELOPER;

/* Akin to glibc's __abort_msg; which is private and we hence cannot
 * use here. */
static char *log_abort_msg = NULL;

void log_set_assert_return_is_critical(bool b) {
        assert_return_is_critical = b;
}

bool log_get_assert_return_is_critical(void) {
        return assert_return_is_critical;
}

static void log_assert(
        int level,
        const char *text,
        const char *file,
        int line,
        const char *func,
        const char *format) {

        static char buffer[LINE_MAX];

        if (_likely_(LOG_PRI(level) > log_get_max_level()))
                return;

        DISABLE_WARNING_FORMAT_NONLITERAL;
        (void) snprintf(buffer, sizeof buffer, format, text, file, line, func);
        REENABLE_WARNING;

        log_abort_msg = buffer;

        log_dispatch_internal(level, 0, file, line, func, NULL, NULL, NULL, NULL, buffer);
}

_noreturn_ void log_assert_failed(const char *text, const char *file, int line, const char *func) {
        log_assert(LOG_CRIT, text, file, line, func,
                   "Assertion '%s' failed at %s:%u, function %s(). Aborting.");
        abort();
}

_noreturn_ void log_assert_failed_unreachable(const char *file, int line, const char *func) {
        log_assert(LOG_CRIT, "Code should not be reached", file, line, func,
                   "%s at %s:%u, function %s(). Aborting. 💥");
        abort();
}

void log_assert_failed_return(const char *text, const char *file, int line, const char *func) {

        if (assert_return_is_critical)
                log_assert_failed(text, file, line, func);

        PROTECT_ERRNO;
        log_assert(LOG_DEBUG, text, file, line, func,
                   "Assertion '%s' failed at %s:%u, function %s(), ignoring.");
}
