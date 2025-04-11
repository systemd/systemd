/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/quota.h>

#include "blockdev-util.h"
#include "path-util.h"
#include "quota-util.h"
#include "rm-rf.h"
#include "tests.h"

static char *runtime_dir = NULL;
STATIC_DESTRUCTOR_REGISTER(runtime_dir, rm_rf_physical_and_freep);

int mkdtemp_malloc(const char *template, char **ret);

TEST(quotactl_devnum) {
        _cleanup_free_ char *dir = NULL;
        _cleanup_free_ char *path = NULL;
        int fd;
        int r;
        dev_t devnum;

        ASSERT_OK(mkdtemp_malloc(NULL, &dir) >= 0);
        path = path_join(dir, ".bin");
        ASSERT_OK(path != NULL);

        int id = getuid();
        ASSERT_OK(id);

        fd = open (path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        ASSERT_OK(fd);
        close(fd);

        r = get_block_device(path, &devnum);
        ASSERT_OK(r);
}

static int intro(void) {
        if (enter_cgroup_subroot(NULL) == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        runtime_dir = setup_fake_runtime_dir();
        ASSERT_OK(runtime_dir != NULL);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
