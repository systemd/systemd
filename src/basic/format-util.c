/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "memory-util.h"
#include "stdio-util.h"
#include "strxcpyx.h"

char* format_bytes_full(char *buf, size_t l, uint64_t t, FormatBytesFlag flag) {
        typedef struct {
                const char *suffix;
                uint64_t factor;
        } suffix_table;
        static const suffix_table table_iec[] = {
                { "E", UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024) },
                { "P", UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024) },
                { "T", UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024) },
                { "G", UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024) },
                { "M", UINT64_C(1024)*UINT64_C(1024) },
                { "K", UINT64_C(1024) },
        }, table_si[] = {
                { "E", UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000) },
                { "P", UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000) },
                { "T", UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000) },
                { "G", UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000) },
                { "M", UINT64_C(1000)*UINT64_C(1000) },
                { "K", UINT64_C(1000) },
        };
        const suffix_table *table;
        size_t n;

        assert_cc(ELEMENTSOF(table_iec) == ELEMENTSOF(table_si));

        if (t == UINT64_MAX)
                return NULL;

        table = flag & FORMAT_BYTES_USE_IEC ? table_iec : table_si;
        n = ELEMENTSOF(table_iec);

        for (size_t i = 0; i < n; i++)
                if (t >= table[i].factor) {
                        uint64_t remainder = i != n - 1 ?
                                (t / table[i + 1].factor * 10 / table[n - 1].factor) % 10 :
                                (t * 10 / table[i].factor) % 10;

                        if (FLAGS_SET(flag, FORMAT_BYTES_BELOW_POINT) && remainder > 0)
                                (void) snprintf(buf, l,
                                                "%" PRIu64 ".%" PRIu64 "%s",
                                                t / table[i].factor,
                                                remainder,
                                                table[i].suffix);
                        else
                                (void) snprintf(buf, l,
                                                "%" PRIu64 "%s",
                                                t / table[i].factor,
                                                table[i].suffix);

                        goto finish;
                }

        (void) snprintf(buf, l, "%" PRIu64 "%s", t, flag & FORMAT_BYTES_TRAILING_B ? "B" : "");

finish:
        buf[l-1] = 0;
        return buf;
}
