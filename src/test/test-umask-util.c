/* SPDX-License-Identifier: LGPL-2.1+ */

#include "tests.h"
#include "umask-util.h"

int main(int argc, char *argv[]) {
        size_t n;
        mode_t u;

        test_setup_logging(LOG_DEBUG);

        u = umask(0111);

        n = 0;
        RUN_WITH_UMASK(0123) {
                assert_se(umask(000) == 0123);
                n++;
        }

        assert_se(n == 1);
        assert_se(umask(u) == 0111);

        RUN_WITH_UMASK(0135) {
                assert_se(umask(000) == 0135);
                n++;
        }

        assert_se(n == 2);
        assert_se(umask(0111) == u);

        RUN_WITH_UMASK(0315) {
                assert_se(umask(000) == 0315);
                n++;
                break;
        }

        assert_se(n == 3);
        assert_se(umask(u) == 0111);

        return EXIT_SUCCESS;
}
