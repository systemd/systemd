/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "percent-util.h"
#include "tests.h"
#include "time-util.h"

TEST(parse_percent) {
        assert_se(parse_percent("") == -EINVAL);
        assert_se(parse_percent("foo") == -EINVAL);
        assert_se(parse_percent("0") == -EINVAL);
        assert_se(parse_percent("0.1") == -EINVAL);
        assert_se(parse_percent("50") == -EINVAL);
        assert_se(parse_percent("100") == -EINVAL);
        assert_se(parse_percent("-1") == -EINVAL);
        assert_se(parse_percent("0%") == 0);
        assert_se(parse_percent("55%") == 55);
        assert_se(parse_percent("100%") == 100);
        assert_se(parse_percent("-7%") == -ERANGE);
        assert_se(parse_percent("107%") == -ERANGE);
        assert_se(parse_percent("%") == -EINVAL);
        assert_se(parse_percent("%%") == -EINVAL);
        assert_se(parse_percent("%1") == -EINVAL);
        assert_se(parse_percent("1%%") == -EINVAL);
        assert_se(parse_percent("3.2%") == -EINVAL);
}

TEST(parse_percent_unbounded) {
        assert_se(parse_percent_unbounded("101%") == 101);
        assert_se(parse_percent_unbounded("400%") == 400);
}

TEST(parse_permille) {
        assert_se(parse_permille("") == -EINVAL);
        assert_se(parse_permille("foo") == -EINVAL);
        assert_se(parse_permille("0") == -EINVAL);
        assert_se(parse_permille("50") == -EINVAL);
        assert_se(parse_permille("100") == -EINVAL);
        assert_se(parse_permille("-1") == -EINVAL);
        assert_se(parse_permille("0.1") == -EINVAL);
        assert_se(parse_permille("5%") == 50);
        assert_se(parse_permille("5.5%") == 55);
        assert_se(parse_permille("5.12%") == -EINVAL);

        assert_se(parse_permille("0‰") == 0);
        assert_se(parse_permille("555‰") == 555);
        assert_se(parse_permille("1000‰") == 1000);
        assert_se(parse_permille("-7‰") == -ERANGE);
        assert_se(parse_permille("1007‰") == -ERANGE);
        assert_se(parse_permille("‰") == -EINVAL);
        assert_se(parse_permille("‰‰") == -EINVAL);
        assert_se(parse_permille("‰1") == -EINVAL);
        assert_se(parse_permille("1‰‰") == -EINVAL);
        assert_se(parse_permille("3.2‰") == -EINVAL);
        assert_se(parse_permille("0.1‰") == -EINVAL);

        assert_se(parse_permille("0%") == 0);
        assert_se(parse_permille("55%") == 550);
        assert_se(parse_permille("55.5%") == 555);
        assert_se(parse_permille("100%") == 1000);
        assert_se(parse_permille("-7%") == -ERANGE);
        assert_se(parse_permille("107%") == -ERANGE);
        assert_se(parse_permille("%") == -EINVAL);
        assert_se(parse_permille("%%") == -EINVAL);
        assert_se(parse_permille("%1") == -EINVAL);
        assert_se(parse_permille("1%%") == -EINVAL);
        assert_se(parse_permille("3.21%") == -EINVAL);
        assert_se(parse_permille("0.1%") == 1);
}

TEST(parse_permille_unbounded) {
        assert_se(parse_permille_unbounded("1001‰") == 1001);
        assert_se(parse_permille_unbounded("4000‰") == 4000);
        assert_se(parse_permille_unbounded("2147483647‰") == 2147483647);
        assert_se(parse_permille_unbounded("2147483648‰") == -ERANGE);
        assert_se(parse_permille_unbounded("4294967295‰") == -ERANGE);
        assert_se(parse_permille_unbounded("4294967296‰") == -ERANGE);

        assert_se(parse_permille_unbounded("101%") == 1010);
        assert_se(parse_permille_unbounded("400%") == 4000);
        assert_se(parse_permille_unbounded("214748364.7%") == 2147483647);
        assert_se(parse_permille_unbounded("214748364.8%") == -ERANGE);
        assert_se(parse_permille_unbounded("429496729.5%") == -ERANGE);
        assert_se(parse_permille_unbounded("429496729.6%") == -ERANGE);
}

TEST(parse_permyriad) {
        assert_se(parse_permyriad("") == -EINVAL);
        assert_se(parse_permyriad("foo") == -EINVAL);
        assert_se(parse_permyriad("0") == -EINVAL);
        assert_se(parse_permyriad("50") == -EINVAL);
        assert_se(parse_permyriad("100") == -EINVAL);
        assert_se(parse_permyriad("-1") == -EINVAL);

        assert_se(parse_permyriad("0‱") == 0);
        assert_se(parse_permyriad("555‱") == 555);
        assert_se(parse_permyriad("1000‱") == 1000);
        assert_se(parse_permyriad("-7‱") == -ERANGE);
        assert_se(parse_permyriad("10007‱") == -ERANGE);
        assert_se(parse_permyriad("‱") == -EINVAL);
        assert_se(parse_permyriad("‱‱") == -EINVAL);
        assert_se(parse_permyriad("‱1") == -EINVAL);
        assert_se(parse_permyriad("1‱‱") == -EINVAL);
        assert_se(parse_permyriad("3.2‱") == -EINVAL);

        assert_se(parse_permyriad("0‰") == 0);
        assert_se(parse_permyriad("555.5‰") == 5555);
        assert_se(parse_permyriad("1000.0‰") == 10000);
        assert_se(parse_permyriad("-7‰") == -ERANGE);
        assert_se(parse_permyriad("1007‰") == -ERANGE);
        assert_se(parse_permyriad("‰") == -EINVAL);
        assert_se(parse_permyriad("‰‰") == -EINVAL);
        assert_se(parse_permyriad("‰1") == -EINVAL);
        assert_se(parse_permyriad("1‰‰") == -EINVAL);
        assert_se(parse_permyriad("3.22‰") == -EINVAL);

        assert_se(parse_permyriad("0%") == 0);
        assert_se(parse_permyriad("55%") == 5500);
        assert_se(parse_permyriad("55.5%") == 5550);
        assert_se(parse_permyriad("55.50%") == 5550);
        assert_se(parse_permyriad("55.53%") == 5553);
        assert_se(parse_permyriad("100%") == 10000);
        assert_se(parse_permyriad("-7%") == -ERANGE);
        assert_se(parse_permyriad("107%") == -ERANGE);
        assert_se(parse_permyriad("%") == -EINVAL);
        assert_se(parse_permyriad("%%") == -EINVAL);
        assert_se(parse_permyriad("%1") == -EINVAL);
        assert_se(parse_permyriad("1%%") == -EINVAL);
        assert_se(parse_permyriad("3.212%") == -EINVAL);
}

TEST(parse_permyriad_unbounded) {
        assert_se(parse_permyriad_unbounded("1001‱") == 1001);
        assert_se(parse_permyriad_unbounded("4000‱") == 4000);
        assert_se(parse_permyriad_unbounded("2147483647‱") == 2147483647);
        assert_se(parse_permyriad_unbounded("2147483648‱") == -ERANGE);
        assert_se(parse_permyriad_unbounded("4294967295‱") == -ERANGE);
        assert_se(parse_permyriad_unbounded("4294967296‱") == -ERANGE);

        assert_se(parse_permyriad_unbounded("101‰") == 1010);
        assert_se(parse_permyriad_unbounded("400‰") == 4000);
        assert_se(parse_permyriad_unbounded("214748364.7‰") == 2147483647);
        assert_se(parse_permyriad_unbounded("214748364.8‰") == -ERANGE);
        assert_se(parse_permyriad_unbounded("429496729.5‰") == -ERANGE);
        assert_se(parse_permyriad_unbounded("429496729.6‰") == -ERANGE);

        assert_se(parse_permyriad_unbounded("99%") == 9900);
        assert_se(parse_permyriad_unbounded("40%") == 4000);
        assert_se(parse_permyriad_unbounded("21474836.47%") == 2147483647);
        assert_se(parse_permyriad_unbounded("21474836.48%") == -ERANGE);
        assert_se(parse_permyriad_unbounded("42949672.95%") == -ERANGE);
        assert_se(parse_permyriad_unbounded("42949672.96%") == -ERANGE);
}

TEST(scale) {
        /* Check some fixed values */
        assert_se(UINT32_SCALE_FROM_PERCENT(0) == 0);
        assert_se(UINT32_SCALE_FROM_PERCENT(50) == UINT32_MAX/2+1);
        assert_se(UINT32_SCALE_FROM_PERCENT(100) == UINT32_MAX);

        assert_se(UINT32_SCALE_FROM_PERMILLE(0) == 0);
        assert_se(UINT32_SCALE_FROM_PERMILLE(500) == UINT32_MAX/2+1);
        assert_se(UINT32_SCALE_FROM_PERMILLE(1000) == UINT32_MAX);

        assert_se(UINT32_SCALE_FROM_PERMYRIAD(0) == 0);
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(5000) == UINT32_MAX/2+1);
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(10000) == UINT32_MAX);

        /* Make sure there's no numeric noise on the 0%…100% scale when converting from percent and back. */
        for (int percent = 0; percent <= 100; percent++) {
                log_debug("%i%% → %" PRIu32 " → %i%%",
                          percent,
                          UINT32_SCALE_FROM_PERCENT(percent),
                          UINT32_SCALE_TO_PERCENT(UINT32_SCALE_FROM_PERCENT(percent)));

                assert_se(UINT32_SCALE_TO_PERCENT(UINT32_SCALE_FROM_PERCENT(percent)) == percent);
        }

        /* Make sure there's no numeric noise on the 0‰…1000‰ scale when converting from permille and back. */
        for (int permille = 0; permille <= 1000; permille++) {
                log_debug("%i‰ → %" PRIu32 " → %i‰",
                          permille,
                          UINT32_SCALE_FROM_PERMILLE(permille),
                          UINT32_SCALE_TO_PERMILLE(UINT32_SCALE_FROM_PERMILLE(permille)));

                assert_se(UINT32_SCALE_TO_PERMILLE(UINT32_SCALE_FROM_PERMILLE(permille)) == permille);
        }

        /* Make sure there's no numeric noise on the 0‱…10000‱ scale when converting from permyriad and back. */
        for (int permyriad = 0; permyriad <= 10000; permyriad++) {
                log_debug("%i‱ → %" PRIu32 " → %i‱",
                          permyriad,
                          UINT32_SCALE_FROM_PERMYRIAD(permyriad),
                          UINT32_SCALE_TO_PERMYRIAD(UINT32_SCALE_FROM_PERMYRIAD(permyriad)));

                assert_se(UINT32_SCALE_TO_PERMYRIAD(UINT32_SCALE_FROM_PERMYRIAD(permyriad)) == permyriad);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
