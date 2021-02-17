/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "percent-util.h"
#include "tests.h"

static void test_parse_percent(void) {
        assert_se(parse_percent("") == -EINVAL);
        assert_se(parse_percent("foo") == -EINVAL);
        assert_se(parse_percent("0") == -EINVAL);
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

static void test_parse_percent_unbounded(void) {
        assert_se(parse_percent_unbounded("101%") == 101);
        assert_se(parse_percent_unbounded("400%") == 400);
}

static void test_parse_permille(void) {
        assert_se(parse_permille("") == -EINVAL);
        assert_se(parse_permille("foo") == -EINVAL);
        assert_se(parse_permille("0") == -EINVAL);
        assert_se(parse_permille("50") == -EINVAL);
        assert_se(parse_permille("100") == -EINVAL);
        assert_se(parse_permille("-1") == -EINVAL);

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
}

static void test_parse_permille_unbounded(void) {
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

static void test_parse_permyriad(void) {
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

static void test_parse_permyriad_unbounded(void) {
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

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_parse_percent();
        test_parse_percent_unbounded();
        test_parse_permille();
        test_parse_permille_unbounded();
        test_parse_permyriad();
        test_parse_permyriad_unbounded();

        return 0;
}
