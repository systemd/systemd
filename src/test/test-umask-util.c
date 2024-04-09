/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "process-util.h"
#include "tests.h"
#include "umask-util.h"

int main(int argc, char *argv[]) {
        size_t n;
        mode_t u, t;

        test_setup_logging(LOG_DEBUG);

        u = umask(0111);

        n = 0;
        WITH_UMASK(0123) {
                ASSERT_EQ(umask(000), 0123u);
                n++;

                assert_se(get_process_umask(0, &t) == 0);
                ASSERT_EQ(t, 000u);
        }

        ASSERT_EQ(n, 1u);
        ASSERT_EQ(umask(u), 0111u);

        assert_se(get_process_umask(getpid_cached(), &t) == 0);
        assert_se(t == u);

        WITH_UMASK(0135) {
                ASSERT_EQ(umask(000), 0135u);
                n++;

                assert_se(get_process_umask(0, &t) == 0);
                ASSERT_EQ(t, 000u);
        }

        ASSERT_EQ(n, 2u);
        assert_se(umask(0111) == u);

        assert_se(get_process_umask(0, &t) == 0);
        ASSERT_EQ(t, 0111u);

        WITH_UMASK(0315) {
                ASSERT_EQ(umask(000), 0315u);
                n++;
                break;
        }

        ASSERT_EQ(n, 3u);
        ASSERT_EQ(umask(u), 0111u);

        assert_se(get_process_umask(0, &t) == 0);
        assert_se(t == u);

        return EXIT_SUCCESS;
}
