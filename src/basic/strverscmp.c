/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strverscmp.h"

#if !defined SD_BOOT
#include <ctype.h>

#include "string-util.h"

typedef bool sd_bool;
#define sd_strcmp(a, b)     strcmp((a), (b))
#define sd_strncmp(a, b, n) strncmp((a), (b), (n))

#else

#include <efi.h>
#include <efilib.h>

typedef BOOLEAN sd_bool;
#define sd_strcmp(a, b)     StrCmp((a), (b))
#define sd_strncmp(a, b, n) StrnCmp((a), (b), (n))

#define XCONCATENATE(x, y) x ## y
#define CONCATENATE(x, y) XCONCATENATE(x, y)

#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#define UNIQ __COUNTER__

#define CMP(a, b) __CMP(UNIQ, (a), UNIQ, (b))
#define __CMP(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? -1 :    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? 1 : 0;  \
        })

#undef MIN
#define MIN(a, b) __MIN(UNIQ, (a), UNIQ, (b))
#define __MIN(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })

static sd_bool isdigit(sd_char a) {
        return a >= '0' && a <= '9';
}

static sd_bool isempty(const sd_char *a) {
        return !a || a[0] == '\0';
}

static sd_int strcmp_ptr(const sd_char *a, const sd_char *b) {
        if (a && b)
                return sd_strcmp(a, b);

        return CMP(a, b);
}
#endif

static sd_bool is_alpha(sd_char a) {
        /* Loocale independent version of isalpha(). */
        return (a >= 'a' && a <= 'z') || (a >= 'A' && a <= 'Z');
}

static sd_bool is_valid_version_char(sd_char a) {
        return isdigit(a) || is_alpha(a) || a == '~' || a ==  '-' || a == '^' || a == '.';
}

sd_int strverscmp_improved(const sd_char *a, const sd_char *b) {

        /* This is based on RPM's rpmvercmp(). But this explicitly handles '-' and '.', as we usually
         * want to directly compare strings which contain both version and release; e.g.
         * '247.2-3.1.fc33.x86_64' or '5.11.0-0.rc5.20210128git76c057c84d28.137.fc34'.
         * Unlike rpmvercmp(), this distiguishes e.g. 123a and 123.a, and 123a is newer.
         *
         * This splits the input strings into segments. Each segment is numeric or alpha, and may be
         * prefixed with the following:
         *  '~' : used for pre-releases, a segment prefixed with this is the oldest,
         *  '-' : used for the separator between version and release,
         *  '^' : used for patched releases, a segment with this is newer than one with '-'.
         *  '.' : used for point releases.
         * Note, no prefix segment is the newest. All non-supported characters are dropped, and
         * handled as a separator of segments, e.g., 123_a is equivalent to 123a.
         *
         * By using this, version strings can be sorted like following:
         *  (older) 122.1
         *     ^    123~rc1-1
         *     |    123
         *     |    123-a
         *     |    123-a.1
         *     |    123-1
         *     |    123-1.1
         *     |    123^post1
         *     |    123.a-1
         *     |    123.1-1
         *     v    123a-1
         *  (newer) 124-1
         */

        if (isempty(a) || isempty(b))
                return strcmp_ptr(a, b);

        for (;;) {
                const sd_char *aa, *bb;
                sd_int r;

                /* Drop leading invalid characters. */
                while (*a != '\0' && !is_valid_version_char(*a))
                        a++;
                while (*b != '\0' && !is_valid_version_char(*b))
                        b++;

                /* Handle '~'. Used for pre-releases, e.g. 123~rc1, or 4.5~alpha1 */
                if (*a == '~' || *b == '~') {
                        /* The string prefixed with '~' is older. */
                        r = CMP(*a != '~', *b != '~');
                        if (r != 0)
                                return r;

                        /* Now both strings are prefixed with '~'. Compare remaining strings. */
                        a++;
                        b++;
                }

                /* If at least one string reaches the end, then longer is newer.
                 * Note that except for '~' prefixed segments, a string has more segments is newer.
                 * So, this check must be after the '~' check. */
                if (*a == '\0' || *b == '\0')
                        return sd_strcmp(a, b);

                /* Handle '-', which separates version and release, e.g 123.4-3.1.fc33.x86_64 */
                if (*a == '-' || *b == '-') {
                        /* The string prefixed with '-' is older (e.g., 123-9 vs 123.1-1) */
                        r = CMP(*a != '-', *b != '-');
                        if (r != 0)
                                return r;

                        a++;
                        b++;
                }

                /* Handle '^'. Used for patched release. */
                if (*a == '^' || *b == '^') {
                        r = CMP(*a != '^', *b != '^');
                        if (r != 0)
                                return r;

                        a++;
                        b++;
                }

                /* Handle '.'. Used for point releases. */
                if (*a == '.' || *b == '.') {
                        r = CMP(*a != '.', *b != '.');
                        if (r != 0)
                                return r;

                        a++;
                        b++;
                }

                if (isdigit(*a) || isdigit(*b)) {
                        /* Skip leading '0', to make 00123 equivalent to 123. */
                        while (*a == '0')
                                a++;
                        while (*b == '0')
                                b++;

                        /* Find the leading numeric segments. One may be an empty string. So,
                         * numeric segments are always newer than alpha segments. */
                        for (aa = a; *aa != '\0' && isdigit(*aa); aa++)
                                ;
                        for (bb = b; *bb != '\0' && isdigit(*bb); bb++)
                                ;

                        /* To compare numeric segments without parsing their values, first compare the
                         * lengths of the segments. Eg. 12345 vs 123, longer is newer. */
                        r = CMP(aa - a, bb - b);
                        if (r != 0)
                                return r;

                        /* Then, compare them as strings. */
                        r = sd_strncmp(a, b, aa - a);
                        if (r != 0)
                                return r;
                } else {
                        /* Find the leading non-numeric segments. */
                        for (aa = a; *aa != '\0' && is_alpha(*aa); aa++)
                                ;
                        for (bb = b; *bb != '\0' && is_alpha(*bb); bb++)
                                ;

                        /* Note that the segments are usually not NUL-terminated. */
                        r = sd_strncmp(a, b, MIN(aa - a, bb - b));
                        if (r != 0)
                                return r;

                        /* Longer is newer, e.g. abc vs abcde. */
                        r = CMP(aa - a, bb - b);
                        if (r != 0)
                                return r;
                }

                /* The current segments are equivalent. Let's compare the next one. */
                a = aa;
                b = bb;
        }
}
