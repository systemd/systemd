/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "calendarspec.h"
#include "fd-util.h"
#include "fuzz.h"
#include "string-util.h"
#include "time-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(calendar_spec_freep) CalendarSpec *cspec = NULL;
        _cleanup_free_ char *str = NULL;
        int r;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        str = memdup_suffix0(data, size);

        size_t l1 = strlen(str);
        const char* usecs = l1 < size ? str + l1 + 1 : "";

        r = calendar_spec_from_string(str, &cspec);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse \"%s\": %m", str);
                return 0;
        }

        _cleanup_free_ char *p = NULL;
        assert_se(calendar_spec_valid(cspec));
        assert_se(calendar_spec_to_string(cspec, &p) == 0);
        assert(p);

        log_debug("spec: %s → %s", str, p);

        _cleanup_(calendar_spec_freep) CalendarSpec *cspec2 = NULL;
        assert_se(calendar_spec_from_string(p, &cspec2) >= 0);
        assert_se(calendar_spec_valid(cspec2));

        usec_t usec = 0;
        (void) parse_time(usecs, &usec, 1);

        /* If timezone is set, calendar_spec_next_usec() would fork, bleh :(
         * Let's not try that. */
        cspec->timezone = mfree(cspec->timezone);

        log_debug("00: %s", strna(FORMAT_TIMESTAMP(usec)));
        for (unsigned i = 1; i <= 20; i++) {
                r = calendar_spec_next_usec(cspec, usec, &usec);
                if (r < 0) {
                        log_debug_errno(r, "%02u: %m", i);
                        break;
                }
                log_debug("%02u: %s", i, FORMAT_TIMESTAMP(usec));
        }

        return 0;
}
