/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "coredump-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "string-table.h"

static const char *const coredump_filter_table[_COREDUMP_FILTER_MAX] = {
        [COREDUMP_FILTER_PRIVATE_ANONYMOUS]   = "private-anonymous",
        [COREDUMP_FILTER_SHARED_ANONYMOUS]    = "shared-anonymous",
        [COREDUMP_FILTER_PRIVATE_FILE_BACKED] = "private-file-backed",
        [COREDUMP_FILTER_SHARED_FILE_BACKED]  = "shared-file-backed",
        [COREDUMP_FILTER_ELF_HEADERS]         = "elf-headers",
        [COREDUMP_FILTER_PRIVATE_HUGE]        = "private-huge",
        [COREDUMP_FILTER_SHARED_HUGE]         = "shared-huge",
        [COREDUMP_FILTER_PRIVATE_DAX]         = "private-dax",
        [COREDUMP_FILTER_SHARED_DAX]          = "shared-dax",
};

DEFINE_STRING_TABLE_LOOKUP(coredump_filter, CoredumpFilter);

int coredump_filter_mask_from_string(const char *s, uint64_t *ret) {
        uint64_t m = 0;

        assert(s);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *n = NULL;
                CoredumpFilter v;
                int r;

                r = extract_first_word(&s, &n, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (streq(n, "default")) {
                        m |= COREDUMP_FILTER_MASK_DEFAULT;
                        continue;
                }

                if (streq(n, "all")) {
                        m = UINT64_MAX;
                        continue;
                }

                v = coredump_filter_from_string(n);
                if (v >= 0) {
                        m |= 1u << v;
                        continue;
                }

                uint64_t x;
                r = safe_atoux64(n, &x);
                if (r < 0)
                        return r;

                m |= x;
        }

        *ret = m;
        return 0;
}

int set_coredump_filter(uint64_t value) {
        char t[STRLEN("0xFFFFFFFF")];

        sprintf(t, "0x%"PRIx64, value);

        return write_string_file("/proc/self/coredump_filter", t,
                                 WRITE_STRING_FILE_VERIFY_ON_FAILURE|WRITE_STRING_FILE_DISABLE_BUFFER);
}
