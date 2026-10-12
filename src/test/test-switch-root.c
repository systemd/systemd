/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "capability-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "switch-root.h"
#include "tests.h"
#include "tmpfile-util.h"

#define FORK_FLAGS                              \
        (FORK_CLOSE_ALL_FDS |                   \
         FORK_RESET_SIGNALS |                   \
         FORK_DEATHSIG_SIGTERM |                \
         FORK_LOG |                             \
         FORK_REOPEN_LOG |                      \
         FORK_WAIT |                            \
         FORK_NEW_MOUNTNS |                     \
         FORK_MOUNTNS_SLAVE)

static void test_switch_root_tmpfs(bool preserve_old_root) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        int r;

        if (geteuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return (void) log_tests_skipped("Not privileged");

        assert_se(mkdtemp_malloc(NULL, &tmp) >= 0);

        r = ASSERT_OK(pidref_safe_fork("(switch-root)", FORK_FLAGS, NULL));
        if (r == 0) {
                _cleanup_close_ int old_root_fd = -EBADF;
                struct stat st;

                assert_se(mount("tmpfs", tmp, "tmpfs", MS_NODEV|MS_NOSUID, "size=16M") >= 0);
                assert_se(chdir(tmp) >= 0);
                assert_se(mkdir("newroot", 0755) >= 0);
                assert_se(touch("old-root-file") >= 0);

                old_root_fd = open(".", O_DIRECTORY|O_CLOEXEC);
                assert_se(old_root_fd >= 0);

                /* Make newroot a mount point so switch_root() can pivot to it. */
                assert_se(mount("newroot", "newroot", NULL, MS_BIND|MS_REC, NULL) >= 0);
                assert_se(chroot(".") >= 0);
                assert_se(chdir("/") >= 0);

                assert_se(switch_root("/newroot",
                                      preserve_old_root ? "/oldroot" : NULL,
                                      SWITCH_ROOT_DESTROY_OLD_ROOT|SWITCH_ROOT_DONT_SYNC) >= 0);

                if (preserve_old_root)
                        assert_se(fstatat(old_root_fd, "old-root-file", &st, AT_SYMLINK_NOFOLLOW) >= 0);
                else
                        assert_se(fstatat(old_root_fd, "old-root-file", &st, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);

                _exit(EXIT_SUCCESS);
        }
}

TEST(switch_root_cleans_temporary_root) {
        test_switch_root_tmpfs(/* preserve_old_root= */ false);
}

TEST(switch_root_preserves_old_root) {
        test_switch_root_tmpfs(/* preserve_old_root= */ true);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
