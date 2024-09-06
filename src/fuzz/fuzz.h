/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "env-util.h"
#include "fileio.h"

/* The entry point into the fuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static inline FILE* data_to_file(const uint8_t *data, size_t size) {
        if (size == 0)
                return fopen("/dev/null", "re");
        else
                return fmemopen_unlocked((char*) data, size, "r");
}

/* Check if we are within the specified size range.
 * The upper limit is ignored if FUZZ_USE_SIZE_LIMIT is unset.
 */
static inline bool outside_size_range(size_t size, size_t lower, size_t upper) {
        if (size < lower)
                return true;
        if (size > upper)
                return FUZZ_USE_SIZE_LIMIT;
        return false;
}

static inline void fuzz_setup_logging(void) {
        /* We don't want to fill the logs and slow down stuff when running
         * in a fuzzing mode, so disable most of the logging. */
        log_set_assert_return_is_critical(true);
        log_set_max_level(LOG_CRIT);
        log_setup();
}

/* Force value to not be optimized away. */
#define DO_NOT_OPTIMIZE(value) ({ asm volatile("" : : "g"(value) : "memory"); })
