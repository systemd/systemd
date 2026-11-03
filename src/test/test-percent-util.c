/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <math.h>

#include "percent-util.h"
#include "tests.h"

TEST(parse_percent) {
        ASSERT_ERROR(parse_percent(""), EINVAL);
        ASSERT_ERROR(parse_percent("foo"), EINVAL);
        ASSERT_ERROR(parse_percent("0"), EINVAL);
        ASSERT_ERROR(parse_percent("0.1"), EINVAL);
        ASSERT_ERROR(parse_percent("50"), EINVAL);
        ASSERT_ERROR(parse_percent("100"), EINVAL);
        ASSERT_ERROR(parse_percent("-1"), EINVAL);
        ASSERT_OK_EQ(parse_percent("0%"), 0);
        ASSERT_OK_EQ(parse_percent("55%"), 55);
        ASSERT_OK_EQ(parse_percent("100%"), 100);
        ASSERT_ERROR(parse_percent("-7%"), ERANGE);
        ASSERT_ERROR(parse_percent("107%"), ERANGE);
        ASSERT_ERROR(parse_percent("%"), EINVAL);
        ASSERT_ERROR(parse_percent("%%"), EINVAL);
        ASSERT_ERROR(parse_percent("%1"), EINVAL);
        ASSERT_ERROR(parse_percent("1%%"), EINVAL);
        ASSERT_ERROR(parse_percent("3.2%"), EINVAL);
}

TEST(parse_percent_unbounded) {
        ASSERT_OK_EQ(parse_percent_unbounded("101%"), 101);
        ASSERT_OK_EQ(parse_percent_unbounded("400%"), 400);
}

TEST(parse_permille) {
        ASSERT_ERROR(parse_permille(""), EINVAL);
        ASSERT_ERROR(parse_permille("foo"), EINVAL);
        ASSERT_ERROR(parse_permille("0"), EINVAL);
        ASSERT_ERROR(parse_permille("50"), EINVAL);
        ASSERT_ERROR(parse_permille("100"), EINVAL);
        ASSERT_ERROR(parse_permille("-1"), EINVAL);
        ASSERT_ERROR(parse_permille("0.1"), EINVAL);
        ASSERT_OK_EQ(parse_permille("5%"), 50);
        ASSERT_OK_EQ(parse_permille("5.5%"), 55);
        ASSERT_ERROR(parse_permille("5.12%"), EINVAL);

        ASSERT_OK_EQ(parse_permille("0‰"), 0);
        ASSERT_OK_EQ(parse_permille("555‰"), 555);
        ASSERT_OK_EQ(parse_permille("1000‰"), 1000);
        ASSERT_ERROR(parse_permille("-7‰"), ERANGE);
        ASSERT_ERROR(parse_permille("1007‰"), ERANGE);
        ASSERT_ERROR(parse_permille("‰"), EINVAL);
        ASSERT_ERROR(parse_permille("‰‰"), EINVAL);
        ASSERT_ERROR(parse_permille("‰1"), EINVAL);
        ASSERT_ERROR(parse_permille("1‰‰"), EINVAL);
        ASSERT_ERROR(parse_permille("3.2‰"), EINVAL);
        ASSERT_ERROR(parse_permille("0.1‰"), EINVAL);

        ASSERT_OK_EQ(parse_permille("0%"), 0);
        ASSERT_OK_EQ(parse_permille("55%"), 550);
        ASSERT_OK_EQ(parse_permille("55.5%"), 555);
        ASSERT_OK_EQ(parse_permille("100%"), 1000);
        ASSERT_ERROR(parse_permille("-7%"), ERANGE);
        ASSERT_ERROR(parse_permille("107%"), ERANGE);
        ASSERT_ERROR(parse_permille("%"), EINVAL);
        ASSERT_ERROR(parse_permille("%%"), EINVAL);
        ASSERT_ERROR(parse_permille("%1"), EINVAL);
        ASSERT_ERROR(parse_permille("1%%"), EINVAL);
        ASSERT_ERROR(parse_permille("3.21%"), EINVAL);
        ASSERT_OK_EQ(parse_permille("0.1%"), 1);
}

TEST(parse_permille_unbounded) {
        ASSERT_OK_EQ(parse_permille_unbounded("1001‰"), 1001);
        ASSERT_OK_EQ(parse_permille_unbounded("4000‰"), 4000);
        ASSERT_OK_EQ(parse_permille_unbounded("2147483647‰"), 2147483647);
        ASSERT_ERROR(parse_permille_unbounded("2147483648‰"), ERANGE);
        ASSERT_ERROR(parse_permille_unbounded("4294967295‰"), ERANGE);
        ASSERT_ERROR(parse_permille_unbounded("4294967296‰"), ERANGE);

        ASSERT_OK_EQ(parse_permille_unbounded("101%"), 1010);
        ASSERT_OK_EQ(parse_permille_unbounded("400%"), 4000);
        ASSERT_OK_EQ(parse_permille_unbounded("214748364.7%"), 2147483647);
        ASSERT_ERROR(parse_permille_unbounded("214748364.8%"), ERANGE);
        ASSERT_ERROR(parse_permille_unbounded("429496729.5%"), ERANGE);
        ASSERT_ERROR(parse_permille_unbounded("429496729.6%"), ERANGE);
}

TEST(parse_permyriad) {
        ASSERT_ERROR(parse_permyriad(""), EINVAL);
        ASSERT_ERROR(parse_permyriad("foo"), EINVAL);
        ASSERT_ERROR(parse_permyriad("0"), EINVAL);
        ASSERT_ERROR(parse_permyriad("50"), EINVAL);
        ASSERT_ERROR(parse_permyriad("100"), EINVAL);
        ASSERT_ERROR(parse_permyriad("-1"), EINVAL);

        ASSERT_OK_EQ(parse_permyriad("0‱"), 0);
        ASSERT_OK_EQ(parse_permyriad("555‱"), 555);
        ASSERT_OK_EQ(parse_permyriad("1000‱"), 1000);
        ASSERT_ERROR(parse_permyriad("-7‱"), ERANGE);
        ASSERT_ERROR(parse_permyriad("10007‱"), ERANGE);
        ASSERT_ERROR(parse_permyriad("‱"), EINVAL);
        ASSERT_ERROR(parse_permyriad("‱‱"), EINVAL);
        ASSERT_ERROR(parse_permyriad("‱1"), EINVAL);
        ASSERT_ERROR(parse_permyriad("1‱‱"), EINVAL);
        ASSERT_ERROR(parse_permyriad("3.2‱"), EINVAL);

        ASSERT_OK_EQ(parse_permyriad("0‰"), 0);
        ASSERT_OK_EQ(parse_permyriad("555.5‰"), 5555);
        ASSERT_OK_EQ(parse_permyriad("1000.0‰"), 10000);
        ASSERT_ERROR(parse_permyriad("-7‰"), ERANGE);
        ASSERT_ERROR(parse_permyriad("1007‰"), ERANGE);
        ASSERT_ERROR(parse_permyriad("‰"), EINVAL);
        ASSERT_ERROR(parse_permyriad("‰‰"), EINVAL);
        ASSERT_ERROR(parse_permyriad("‰1"), EINVAL);
        ASSERT_ERROR(parse_permyriad("1‰‰"), EINVAL);
        ASSERT_ERROR(parse_permyriad("3.22‰"), EINVAL);

        ASSERT_OK_EQ(parse_permyriad("0%"), 0);
        ASSERT_OK_EQ(parse_permyriad("55%"), 5500);
        ASSERT_OK_EQ(parse_permyriad("55.5%"), 5550);
        ASSERT_OK_EQ(parse_permyriad("55.50%"), 5550);
        ASSERT_OK_EQ(parse_permyriad("55.53%"), 5553);
        ASSERT_OK_EQ(parse_permyriad("100%"), 10000);
        ASSERT_ERROR(parse_permyriad("-7%"), ERANGE);
        ASSERT_ERROR(parse_permyriad("107%"), ERANGE);
        ASSERT_ERROR(parse_permyriad("%"), EINVAL);
        ASSERT_ERROR(parse_permyriad("%%"), EINVAL);
        ASSERT_ERROR(parse_permyriad("%1"), EINVAL);
        ASSERT_ERROR(parse_permyriad("1%%"), EINVAL);
        ASSERT_ERROR(parse_permyriad("3.212%"), EINVAL);
}

TEST(parse_permyriad_unbounded) {
        ASSERT_OK_EQ(parse_permyriad_unbounded("1001‱"), 1001);
        ASSERT_OK_EQ(parse_permyriad_unbounded("4000‱"), 4000);
        ASSERT_OK_EQ(parse_permyriad_unbounded("2147483647‱"), 2147483647);
        ASSERT_ERROR(parse_permyriad_unbounded("2147483648‱"), ERANGE);
        ASSERT_ERROR(parse_permyriad_unbounded("4294967295‱"), ERANGE);
        ASSERT_ERROR(parse_permyriad_unbounded("4294967296‱"), ERANGE);

        ASSERT_OK_EQ(parse_permyriad_unbounded("101‰"), 1010);
        ASSERT_OK_EQ(parse_permyriad_unbounded("400‰"), 4000);
        ASSERT_OK_EQ(parse_permyriad_unbounded("214748364.7‰"), 2147483647);
        ASSERT_ERROR(parse_permyriad_unbounded("214748364.8‰"), ERANGE);
        ASSERT_ERROR(parse_permyriad_unbounded("429496729.5‰"), ERANGE);
        ASSERT_ERROR(parse_permyriad_unbounded("429496729.6‰"), ERANGE);

        ASSERT_OK_EQ(parse_permyriad_unbounded("99%"), 9900);
        ASSERT_OK_EQ(parse_permyriad_unbounded("40%"), 4000);
        ASSERT_OK_EQ(parse_permyriad_unbounded("21474836.47%"), 2147483647);
        ASSERT_ERROR(parse_permyriad_unbounded("21474836.48%"), ERANGE);
        ASSERT_ERROR(parse_permyriad_unbounded("42949672.95%"), ERANGE);
        ASSERT_ERROR(parse_permyriad_unbounded("42949672.96%"), ERANGE);
}

TEST(scale) {
        /* Check some fixed values */
        ASSERT_EQ(UINT32_SCALE_FROM_PERCENT(/* percent= */ 0), 0U);
        ASSERT_EQ(UINT32_SCALE_FROM_PERCENT(50), UINT32_MAX/2+1);
        ASSERT_EQ(UINT32_SCALE_FROM_PERCENT(100), UINT32_MAX);

        ASSERT_EQ(UINT32_SCALE_FROM_PERMILLE(/* permille= */ 0), 0U);
        ASSERT_EQ(UINT32_SCALE_FROM_PERMILLE(500), UINT32_MAX/2+1);
        ASSERT_EQ(UINT32_SCALE_FROM_PERMILLE(1000), UINT32_MAX);

        ASSERT_EQ(UINT32_SCALE_FROM_PERMYRIAD(/* permyriad= */ 0), 0U);
        ASSERT_EQ(UINT32_SCALE_FROM_PERMYRIAD(5000), UINT32_MAX/2+1);
        ASSERT_EQ(UINT32_SCALE_FROM_PERMYRIAD(10000), UINT32_MAX);

        /* Make sure there's no numeric noise on the 0%…100% scale when converting from percent and back. */
        for (int percent = 0; percent <= 100; percent++) {
                log_debug("%i%% → %" PRIu32 " → %i%%",
                          percent,
                          UINT32_SCALE_FROM_PERCENT(percent),
                          UINT32_SCALE_TO_PERCENT(UINT32_SCALE_FROM_PERCENT(percent)));

                ASSERT_EQ(UINT32_SCALE_TO_PERCENT(UINT32_SCALE_FROM_PERCENT(percent)), percent);
        }

        /* Make sure there's no numeric noise on the 0‰…1000‰ scale when converting from permille and back. */
        for (int permille = 0; permille <= 1000; permille++) {
                log_debug("%i‰ → %" PRIu32 " → %i‰",
                          permille,
                          UINT32_SCALE_FROM_PERMILLE(permille),
                          UINT32_SCALE_TO_PERMILLE(UINT32_SCALE_FROM_PERMILLE(permille)));

                ASSERT_EQ(UINT32_SCALE_TO_PERMILLE(UINT32_SCALE_FROM_PERMILLE(permille)), permille);
        }

        /* Make sure there's no numeric noise on the 0‱…10000‱ scale when converting from permyriad and back. */
        for (int permyriad = 0; permyriad <= 10000; permyriad++) {
                log_debug("%i‱ → %" PRIu32 " → %i‱",
                          permyriad,
                          UINT32_SCALE_FROM_PERMYRIAD(permyriad),
                          UINT32_SCALE_TO_PERMYRIAD(UINT32_SCALE_FROM_PERMYRIAD(permyriad)));

                ASSERT_EQ(UINT32_SCALE_TO_PERMYRIAD(UINT32_SCALE_FROM_PERMYRIAD(permyriad)), permyriad);
        }

        ASSERT_EQ(DOUBLE_SCALE_TO_PERMYRIAD(0.0), 0);
        ASSERT_EQ(DOUBLE_SCALE_TO_PERMYRIAD(0.125), 1250);
        ASSERT_EQ(DOUBLE_SCALE_TO_PERMYRIAD(0.33333), 3333);
        ASSERT_EQ(DOUBLE_SCALE_TO_PERMYRIAD(0.66666), 6667);
        ASSERT_EQ(DOUBLE_SCALE_TO_PERMYRIAD(1.0), 10000);
        ASSERT_ERROR(DOUBLE_SCALE_TO_PERMYRIAD(1.0001), ERANGE);
        ASSERT_ERROR(DOUBLE_SCALE_TO_PERMYRIAD(-0.0001), ERANGE);
        ASSERT_ERROR(DOUBLE_SCALE_TO_PERMYRIAD(NAN), ERANGE);

        ASSERT_EQ(UINT32_RATIO_TO_PERMYRIAD(/* value= */ 0, 10000), 0);
        ASSERT_EQ(UINT32_RATIO_TO_PERMYRIAD(5000, 10000), 5000);
        ASSERT_EQ(UINT32_RATIO_TO_PERMYRIAD(10000, 10000), 10000);
        ASSERT_EQ(UINT32_RATIO_TO_PERMYRIAD(1, 3), 3333);
        ASSERT_EQ(UINT32_RATIO_TO_PERMYRIAD(2, 3), 6667);
        ASSERT_EQ(UINT32_RATIO_TO_PERMYRIAD(UINT32_MAX/2, UINT32_MAX), 5000);
        ASSERT_EQ(UINT32_RATIO_TO_PERMYRIAD(UINT32_MAX, UINT32_MAX), 10000);
        ASSERT_ERROR(UINT32_RATIO_TO_PERMYRIAD(2, 1), ERANGE);
        ASSERT_ERROR(UINT32_RATIO_TO_PERMYRIAD(1, /* scale= */ 0), ERANGE);
        ASSERT_ERROR(UINT32_RATIO_TO_PERMYRIAD(1, (uint64_t) UINT32_MAX + 1), ERANGE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
