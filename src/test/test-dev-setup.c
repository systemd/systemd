/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "capability-util.h"
#include "dev-setup.h"
#include "fs-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        const char *f;
        struct stat st;

        test_setup_logging(LOG_DEBUG);

        if (have_effective_cap(CAP_DAC_OVERRIDE) <= 0)
                return log_tests_skipped("missing capability (CAP_DAC_OVERRIDE)");

        ASSERT_OK(mkdtemp_malloc("/tmp/test-dev-setupXXXXXX", &p));

        f = prefix_roota(p, "/run/systemd");
        ASSERT_OK(mkdir_p(f, 0755));

        ASSERT_OK(make_inaccessible_nodes(f, 1, 1));
        ASSERT_OK(make_inaccessible_nodes(f, 1, 1)); /* 2nd call should be a clean NOP */

        f = prefix_roota(p, "/run/systemd/inaccessible/reg");
        ASSERT_OK_ERRNO(stat(f, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_EQ((st.st_mode & 07777), 0000U);

        f = prefix_roota(p, "/run/systemd/inaccessible/dir");
        ASSERT_OK_ERRNO(stat(f, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_EQ((st.st_mode & 07777), 0000U);

        f = prefix_roota(p, "/run/systemd/inaccessible/fifo");
        ASSERT_OK_ERRNO(stat(f, &st));
        ASSERT_TRUE(S_ISFIFO(st.st_mode));
        ASSERT_EQ((st.st_mode & 07777), 0000U);

        f = prefix_roota(p, "/run/systemd/inaccessible/sock");
        ASSERT_OK_ERRNO(stat(f, &st));
        ASSERT_TRUE(S_ISSOCK(st.st_mode));
        ASSERT_EQ((st.st_mode & 07777), 0000U);

        f = prefix_roota(p, "/run/systemd/inaccessible/chr");
        if (stat(f, &st) < 0)
                ASSERT_EQ(errno, ENOENT);
        else {
                ASSERT_TRUE(S_ISCHR(st.st_mode));
                ASSERT_EQ((st.st_mode & 07777), 0000U);
        }

        f = prefix_roota(p, "/run/systemd/inaccessible/blk");
        if (stat(f, &st) < 0)
                ASSERT_EQ(errno, ENOENT);
        else {
                ASSERT_TRUE(S_ISBLK(st.st_mode));
                ASSERT_EQ((st.st_mode & 07777), 0000U);
        }

        return EXIT_SUCCESS;
}
