/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/stat.h>

#include "capability-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mountpoint-util.h"
#include "mstack.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "virt.h"

static bool overlayfs_set_fd_lowerdir_plus_supported(void) {
        int r;

        _cleanup_close_ int sb_fd = fsopen("overlay", FSOPEN_CLOEXEC);
        if (sb_fd < 0 && (ERRNO_IS_NOT_SUPPORTED(errno) || errno == ENODEV))
                return false;
        ASSERT_OK_ERRNO(sb_fd);

        _cleanup_close_ int layer_fd = open("/", O_DIRECTORY|O_CLOEXEC);
        ASSERT_OK_ERRNO(layer_fd);

        r = RET_NERRNO(fsconfig(sb_fd, FSCONFIG_SET_FD, "lowerdir+", /* value= */ NULL, layer_fd));
        if (r < 0 && (ERRNO_IS_NEG_NOT_SUPPORTED(r) || r == -EINVAL))
                return false;

        ASSERT_OK_ERRNO(r);
        return true;
}

TEST(mstack) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        int r;

        tfd = mkdtemp_open("/tmp/mstack-what-XXXXXX", O_PATH, &t);
        ASSERT_OK(tfd);

        ASSERT_OK_ERRNO(mkdirat(tfd, "rw", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "rw/data", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "rw/data/check1", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0/check2", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0/zzz", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@1", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@1/check3", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0/yyy", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "bind@zzz", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "bind@zzz/check4", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "robind@yyy", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "robind@yyy/check5", 0755));

        _cleanup_(mstack_freep) MStack *mstack = NULL;
        ASSERT_OK(mstack_load(t, tfd, &mstack));

        ASSERT_OK_ZERO(mstack_is_read_only(mstack));
        ASSERT_OK_ZERO(mstack_is_foreign_uid_owned(mstack));

        if (!have_effective_cap(CAP_SYS_ADMIN))
                return (void) log_tests_skipped("not attaching mstack, lacking privs");
        if (!mount_new_api_supported())
                return (void) log_tests_skipped("kernel does not support new mount API, skipping mstack attachment test.");
        if (!overlayfs_set_fd_lowerdir_plus_supported())
                return (void) log_tests_skipped("overlayfs does not support FSCONFIG_SET_FD with lowerdir+, skipping mstack attachment test.");
        if (running_in_chroot() > 0) /* we cannot disable mount prop if we are in a chroot without the root inode being a proper mount point */
                return (void) log_tests_skipped("running in chroot(), skipping mstack attachment test.");

        mstack = mstack_free(mstack);

        /* For with a new mountns */
        r = pidref_safe_fork("(mstack-test", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, /* ret= */ NULL);
        ASSERT_OK(r);

        if (r == 0) {
                MStackFlags flags = 0;

                /* Close the original temporary fd, it still points to an inode of the original mountns,
                 * which we cannot use to generate mounts from */
                tfd = safe_close(tfd);

                {
                        ASSERT_OK(mstack_load(t, -EBADF, &mstack));

                        ASSERT_OK(mstack_open_images(
                                                  mstack,
                                                  /* mountfsd_link= */ NULL,
                                                  /* userns_fd= */ -EBADF,
                                                  /* image_policy= */ NULL,
                                                  /* image_filter= */ NULL,
                                                  flags));

                        _cleanup_(rmdir_and_freep) char *m = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-temporary-XXXXXX", &m));

                        ASSERT_OK(mstack_make_mounts(mstack, m, flags));

                        _cleanup_(rmdir_and_freep) char *w = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-where-XXXXXX", &w));

                        _cleanup_close_ int rfd = -EBADF;
                        ASSERT_OK(mstack_bind_mounts(mstack, w, /* where_fd= */ -EBADF, flags, &rfd));

                        _cleanup_close_ int ofd = open(w, O_PATH|O_CLOEXEC);
                        ASSERT_OK_ERRNO(ofd);

                        ASSERT_OK_ERRNO(faccessat(ofd, "check1", F_OK, AT_SYMLINK_NOFOLLOW));
                        ASSERT_OK_ERRNO(faccessat(ofd, "check2/", F_OK, AT_SYMLINK_NOFOLLOW));
                        ASSERT_OK_ERRNO(faccessat(ofd, "check3/", F_OK, AT_SYMLINK_NOFOLLOW));
                        ASSERT_OK_ERRNO(faccessat(ofd, "zzz/check4/", F_OK, AT_SYMLINK_NOFOLLOW));
                        ASSERT_OK_ERRNO(faccessat(ofd, "yyy/check5/", F_OK, AT_SYMLINK_NOFOLLOW));

                        _cleanup_free_ char *j = ASSERT_PTR(path_join(w, "zzz"));
                        ASSERT_OK_ERRNO(umount2(j, MNT_DETACH));
                        _cleanup_free_ char *jj = ASSERT_PTR(path_join(w, "yyy"));
                        ASSERT_OK_ERRNO(umount2(jj, MNT_DETACH));
                        ASSERT_OK_ERRNO(umount2(w, MNT_DETACH));
                }

                mstack = mstack_free(mstack);

                _exit(EXIT_SUCCESS);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
