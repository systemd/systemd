/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "calendarspec.h"
#include "fd-util.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(calendar_spec_freep) CalendarSpec *cspec = NULL;
        _cleanup_free_ char *str = NULL, *p = NULL;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        str = memdup_suffix0(data, size);

        if (calendar_spec_from_string(str, &cspec) >= 0) {
                (void) calendar_spec_valid(cspec);
                (void) calendar_spec_normalize(cspec);
                (void) calendar_spec_to_string(cspec, &p);
        }

        return 0;
}
