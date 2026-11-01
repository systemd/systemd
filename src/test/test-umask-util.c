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
                ASSERT_EQ(umask(000), 0123U);
                n++;

                ASSERT_OK_ZERO(get_process_umask(/* pid= */ 0, &t));
                ASSERT_EQ(t, 000U);
        }

        ASSERT_EQ(n, 1U);
        ASSERT_EQ(umask(u), 0111U);

        ASSERT_OK_ZERO(get_process_umask(getpid_cached(), &t));
        ASSERT_EQ(t, u);

        WITH_UMASK(0135) {
                ASSERT_EQ(umask(000), 0135U);
                n++;

                ASSERT_OK_ZERO(get_process_umask(/* pid= */ 0, &t));
                ASSERT_EQ(t, 000U);
        }

        ASSERT_EQ(n, 2U);
        ASSERT_EQ(umask(0111), u);

        ASSERT_OK_ZERO(get_process_umask(/* pid= */ 0, &t));
        ASSERT_EQ(t, 0111U);

        WITH_UMASK(0315) {
                ASSERT_EQ(umask(000), 0315U);
                n++;
                break;
        }

        ASSERT_EQ(n, 3U);
        ASSERT_EQ(umask(u), 0111U);

        ASSERT_OK_ZERO(get_process_umask(/* pid= */ 0, &t));
        ASSERT_EQ(t, u);

        return EXIT_SUCCESS;
}
