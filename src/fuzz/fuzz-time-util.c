/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fuzz.h"
#include "time-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *str = NULL;
        usec_t usec;

        fuzz_setup_logging();

        assert_se(str = memdup_suffix0(data, size));

        (void) parse_timestamp(str, &usec);
        (void) parse_sec(str, &usec);
        (void) parse_sec_fix_0(str, &usec);
        (void) parse_sec_def_infinity(str, &usec);
        (void) parse_time(str, &usec, USEC_PER_SEC);
        (void) parse_nsec(str, &usec);

        (void) timezone_is_valid(str, LOG_DEBUG);

        return 0;
}
