/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "hexdump.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "memstream-util.h"

void hexdump(FILE *f, const void *p, size_t s) {
        const uint8_t *b = p;
        unsigned n = 0;

        assert(b || s == 0);

        if (s == SIZE_MAX)
                s = strlen(p);

        if (!f)
                f = stdout;

        while (s > 0) {
                size_t i;

                fprintf(f, "%04x  ", n);

                for (i = 0; i < 16; i++) {

                        if (i >= s)
                                fputs("   ", f);
                        else
                                fprintf(f, "%02x ", b[i]);

                        if (i == 7)
                                fputc(' ', f);
                }

                fputc(' ', f);

                for (i = 0; i < 16; i++) {

                        if (i >= s)
                                fputc(' ', f);
                        else
                                fputc(isprint(b[i]) ? (char) b[i] : '.', f);
                }

                fputc('\n', f);

                if (s < 16)
                        break;

                n += 16;
                b += 16;
                s -= 16;
        }
}

static void dump_hex_line(FILE *f, char tag, const uint8_t *p, size_t size, size_t off) {
        assert(f);

        fprintf(f, "%c %04zx  ", tag, off);

        for (size_t i = 0; i < 16; i++) {
                if (off + i < size)
                        fprintf(f, "%02x ", p[off + i]);
                else
                        fputs("   ", f);

                if (i == 7)
                        fputc(' ', f);
        }

        fputs(" |", f);
        for (size_t i = 0; i < 16; i++) {
                if (off + i < size) {
                        uint8_t c = p[off + i];
                        fputc(isprint(c) ? (char) c : '.', f);
                } else
                        fputc(' ', f);
        }
        fputs("|\n", f);
}

char* hexdump_memcmp(const void *m1, size_t l1, const void *m2, size_t l2) {
        _cleanup_(memstream_done) MemStream m = {};
        const uint8_t *a = m1, *b = m2;
        size_t mx = MAX(l1, l2);
        FILE *f;

        /* Returns a hexdump(3)-like side-by-side representation of two memory regions. For each 16 byte
         * chunk that differs a marker line pointing at the diverging bytes ('<' is the first region, '>' the
         * second) is appended. */

        f = memstream_init(&m);
        if (!f)
                return NULL;

        for (size_t off = 0; off < mx; off += 16) {
                dump_hex_line(f, '<', a, l1, off);
                dump_hex_line(f, '>', b, l2, off);

                /* Figure out whether this chunk differs at all, and only then emit the marker line. */
                bool any = false;
                for (size_t i = 0; i < 16 && off + i < mx; i++) {
                        bool pa = off + i < l1, pb = off + i < l2;
                        if (pa != pb || (pa && pb && a[off + i] != b[off + i])) {
                                any = true;
                                break;
                        }
                }
                if (!any)
                        continue;

                fputs("        ", f); /* align with the 8-char "%c %04zx  " prefix: tag + space + 4 hex + 2 spaces */
                for (size_t i = 0; i < 16; i++) {
                        bool pa = off + i < l1, pb = off + i < l2;
                        bool diff = pa != pb || (pa && pb && a[off + i] != b[off + i]);
                        fputs(diff ? "^^ " : "   ", f);

                        if (i == 7)
                                fputc(' ', f);
                }
                fputc('\n', f);
        }

        char *ret;
        if (memstream_finalize(&m, &ret, /* ret_size= */ NULL) < 0)
                return NULL;

        return ret;
}

char* hexdump_memcmp_byte(uint8_t byte, const void *data, size_t length) {
        _cleanup_free_ uint8_t *expected = NULL;

        /* Like hexdump_memcmp(), but compares the memory region against a region of the same length filled
         * with 'byte'. Used by ASSERT_MEMEQ_BYTE() and ASSERT_MEMEQ_ZERO(). */

        if (length > 0) {
                expected = malloc(length);
                if (!expected)
                        return NULL;
                memset(expected, byte, length);
        }

        return hexdump_memcmp(data, length, expected, length);
}

char* hexdump_iovw_compare(const struct iovec_wrapper *a, const struct iovec_wrapper *b) {
        _cleanup_(memstream_done) MemStream m = {};
        size_t na = a ? a->count : 0, nb = b ? b->count : 0, mx = MAX(na, nb);
        FILE *f;

        /* Dumps the elements of two iovec wrappers that differ, element by element, reusing
         * hexdump_memcmp(). Used by ASSERT_IOVW_EQ(). */

        f = memstream_init(&m);
        if (!f)
                return NULL;

        for (size_t i = 0; i < mx; i++) {
                const struct iovec *ia = i < na ? a->iovec + i : NULL;
                const struct iovec *ib = i < nb ? b->iovec + i : NULL;

                if (ia && ib && iovec_memcmp(ia, ib) == 0)
                        continue;

                _cleanup_free_ char *d = hexdump_memcmp(ia ? ia->iov_base : NULL, ia ? ia->iov_len : 0,
                                                        ib ? ib->iov_base : NULL, ib ? ib->iov_len : 0);
                fprintf(f, "element %zu differs:\n%s", i, d ?: "");
        }

        char *ret;
        if (memstream_finalize(&m, &ret, /* ret_size= */ NULL) < 0)
                return NULL;

        return ret;
}
