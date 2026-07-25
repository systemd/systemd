/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "capability-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "mstack.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "virt.h"

static bool overlayfs_lowerdir_plus_supported(void) {
        int r;

        _cleanup_close_ int sb_fd = fsopen("overlay", FSOPEN_CLOEXEC);
        if (sb_fd < 0 && (ERRNO_IS_NOT_SUPPORTED(errno) || errno == ENODEV))
                return false;
        ASSERT_OK_ERRNO(sb_fd);

        _cleanup_close_ int layer_fd = open("/", O_DIRECTORY|O_CLOEXEC);
        ASSERT_OK_ERRNO(layer_fd);

        /* Try FSCONFIG_SET_FD first (kernel 6.13+) */
        r = RET_NERRNO(fsconfig(sb_fd, FSCONFIG_SET_FD, "lowerdir+", /* value= */ NULL, layer_fd));
        if (r >= 0)
                return true;
        if (r != -EBADF && r != -EINVAL && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return false;

        /* Fall back to string path (kernel 6.5+) */
        return RET_NERRNO(fsconfig(sb_fd, FSCONFIG_SET_STRING, "lowerdir+", FORMAT_PROC_FD_PATH(layer_fd), /* aux= */ 0)) >= 0;
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
        ASSERT_OK_ERRNO(mkdirat(tfd, "tmpfs@ttt", 0755));

        _cleanup_(mstack_freep) MStack *mstack = NULL;
        ASSERT_OK(mstack_load(t, tfd, &mstack));

        ASSERT_OK_ZERO(mstack_is_read_only(mstack));
        ASSERT_OK_ZERO(mstack_is_foreign_uid_owned(mstack));

        MStackMount *tmpfs_mount = NULL;
        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                if (m->mount_type == MSTACK_TMPFS)
                        tmpfs_mount = m;
        ASSERT_TRUE(tmpfs_mount);
        ASSERT_STREQ(tmpfs_mount->where, "/ttt");

        if (!have_effective_cap(CAP_SYS_ADMIN))
                return (void) log_tests_skipped("not attaching mstack, lacking privs");
        if (!mount_new_api_supported())
                return (void) log_tests_skipped("kernel does not support new mount API, skipping mstack attachment test.");
        if (!overlayfs_lowerdir_plus_supported())
                return (void) log_tests_skipped("overlayfs does not support lowerdir+, skipping mstack attachment test.");
        if (running_in_chroot() > 0) /* we cannot disable mount prop if we are in a chroot without the root inode being a proper mount point */
                return (void) log_tests_skipped("running in chroot(), skipping mstack attachment test.");

        mstack = mstack_free(mstack);

        /* pidref_safe_fork() blocks further dlopen() in the child by default. Realizing the tmpfs@ entry
         * below goes through make_fsmount() -> mount_option_mangle(), which lazily dlopen()s libmount; warm
         * that up here in the parent (as real nspawn invocations already have, by the time they get this
         * far) so the child's call finds it already loaded instead of failing with EOPNOTSUPP. */
        {
                unsigned long mf;
                _cleanup_free_ char *mo = NULL;
                (void) mount_option_mangle("mode=0755", 0, &mf, &mo);
        }

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

                        ASSERT_OK(mstack_make_mounts(mstack, m, flags, /* uid_shift= */ UID_INVALID));

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
                        ASSERT_OK_ERRNO(faccessat(ofd, "ttt/", F_OK, AT_SYMLINK_NOFOLLOW));

                        /* tmpfs@ has no on-disk backing, so unlike bind@/robind@ it must be a fresh,
                         * empty, writable tmpfs rather than a copy of anything from the source tree. */
                        _cleanup_free_ char *ttt = ASSERT_PTR(path_join(w, "ttt"));
                        ASSERT_OK_POSITIVE(path_is_fs_type(ttt, TMPFS_MAGIC));
                        _cleanup_free_ char *ttt_probe = ASSERT_PTR(path_join(ttt, "probe"));
                        ASSERT_OK_ERRNO(mkdir(ttt_probe, 0755));

                        _cleanup_free_ char *j = ASSERT_PTR(path_join(w, "zzz"));
                        ASSERT_OK_ERRNO(umount2(j, MNT_DETACH));
                        _cleanup_free_ char *jj = ASSERT_PTR(path_join(w, "yyy"));
                        ASSERT_OK_ERRNO(umount2(jj, MNT_DETACH));
                        _cleanup_free_ char *jjj = ASSERT_PTR(path_join(w, "ttt"));
                        ASSERT_OK_ERRNO(umount2(jjj, MNT_DETACH));
                        ASSERT_OK_ERRNO(umount2(w, MNT_DETACH));
                }

                mstack = mstack_free(mstack);

                _exit(EXIT_SUCCESS);
        }
}

TEST(mstack_new_from_root_fd) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        tfd = mkdtemp_open("/tmp/mstack-root-fd-XXXXXX", O_PATH, &t);
        ASSERT_OK(tfd);

        int root_fd = open(t, O_PATH|O_DIRECTORY|O_CLOEXEC);
        ASSERT_OK_ERRNO(root_fd);
        int root_fd_value = root_fd;

        _cleanup_(mstack_freep) MStack *mstack = NULL;
        ASSERT_OK(mstack_new_from_root_fd(TAKE_FD(root_fd), &mstack));

        /* Single MSTACK_ROOT entry, ownership of root_fd transferred into mount_fd. */
        ASSERT_EQ(mstack->n_mounts, 1u);
        ASSERT_EQ(mstack->mounts[0].mount_type, MSTACK_ROOT);
        ASSERT_EQ(mstack->mounts[0].mount_fd, root_fd_value);
        ASSERT_TRUE(mstack->root_mount == &mstack->mounts[0]);
        ASSERT_FALSE(mstack->has_tmpfs_root);
        ASSERT_FALSE(mstack->has_overlayfs);
}

TEST(mstack_merge_volatile) {
        /* --volatile=overlay: existing root demoted to a lower layer, plus a synthetic rw upper. */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-overlay-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                int root_fd = open(t, O_PATH|O_DIRECTORY|O_CLOEXEC);
                ASSERT_OK_ERRNO(root_fd);

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_new_from_root_fd(TAKE_FD(root_fd), &mstack));

                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_OVERLAY, UID_INVALID, /* tmpfs_selinux_context= */ NULL));

                ASSERT_EQ(mstack->n_mounts, 2u);
                bool has_layer = false, has_rw = false;
                FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                        if (m->mount_type == MSTACK_LAYER)
                                has_layer = true;
                        else if (m->mount_type == MSTACK_RW)
                                has_rw = true;
                }
                ASSERT_TRUE(has_layer);
                ASSERT_TRUE(has_rw);
                ASSERT_TRUE(mstack->has_overlayfs);
        }

        /* --volatile=state: root kept read-only, fresh tmpfs@/var added on top. */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-state-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                int root_fd = open(t, O_PATH|O_DIRECTORY|O_CLOEXEC);
                ASSERT_OK_ERRNO(root_fd);

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_new_from_root_fd(TAKE_FD(root_fd), &mstack));

                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_STATE, UID_INVALID, /* tmpfs_selinux_context= */ NULL));

                ASSERT_EQ(mstack->n_mounts, 2u);
                MStackMount *var_tmpfs = NULL;
                FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                        if (m->mount_type == MSTACK_TMPFS)
                                var_tmpfs = m;
                ASSERT_TRUE(var_tmpfs);
                ASSERT_STREQ(var_tmpfs->where, "/var");

                ASSERT_TRUE(mstack->root_mount);
                ASSERT_EQ(mstack->root_mount->mount_type, MSTACK_ROOT);
        }

        /* --volatile=yes, no root/ entry (just layer@ content that already only ever represented /usr/):
         * mstack_merge_volatile() alone only validates and marks extract_usr_only - root/ (if any) is now
         * folded directly into the overlay alongside layer@/rw (see the VOLATILE_OVERLAY/c0e065d4fd
         * merge), so there's no single pre-assembly entry left to cleanly pull /usr/ out of; the actual
         * extraction happens later, from the fully assembled tree, inside mstack_make_mounts() (verified
         * below, gated on privileges since it needs a real overlay mount). */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-yes-nolayer-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0", 0755));
                ASSERT_OK_ERRNO(mkdirat(tfd, "layer@1", 0755));

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));
                ASSERT_FALSE(mstack->root_mount);
                ASSERT_FALSE(mstack->has_tmpfs_root);
                ASSERT_TRUE(mstack->has_overlayfs);
                ASSERT_FALSE(mstack->extract_usr_only);

                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_YES, UID_INVALID, /* tmpfs_selinux_context= */ NULL));

                ASSERT_TRUE(mstack->extract_usr_only);
                ASSERT_TRUE(mstack->has_overlayfs);
                ASSERT_TRUE(mstack->usr_extract_fd < 0); /* not realized yet, only mstack_make_mounts() does that */

                size_t n_layers = 0;
                FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                        if (m->mount_type == MSTACK_LAYER)
                                n_layers++;
                ASSERT_EQ(n_layers, 2u);
        }

        /* --volatile=yes, with a root/ entry: after the tree is fully assembled (root/ folded into the
         * overlay as its base layer, per c0e065d4fd), /usr/ is cloned out of the assembled result read-only
         * into usr_extract_fd, and root_mount_fd is replaced with a throwaway tmpfs. Needs a real overlay
         * assembly (fsopen()/fsconfig()/open_tree(OPEN_TREE_CLONE)), hence gated. */
        if (!have_effective_cap(CAP_SYS_ADMIN))
                return (void) log_tests_skipped("not merging volatile=yes with a root/ entry, lacking privs");
        if (!mount_new_api_supported())
                return (void) log_tests_skipped("kernel does not support new mount API, skipping volatile=yes root/ merge test.");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("running in chroot(), skipping volatile=yes root/ merge test.");

        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-yes-root-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);
                ASSERT_OK_ERRNO(mkdirat(tfd, "usr", 0755));

                int root_fd = open(t, O_PATH|O_DIRECTORY|O_CLOEXEC);
                ASSERT_OK_ERRNO(root_fd);

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_new_from_root_fd(TAKE_FD(root_fd), &mstack));

                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_YES, UID_INVALID, /* tmpfs_selinux_context= */ NULL));

                /* Merging alone doesn't touch the mount list or realize anything yet - the root/ entry
                 * (folded into the overlay assembly below) is still there. */
                ASSERT_TRUE(mstack->extract_usr_only);
                ASSERT_TRUE(mstack->root_mount);
                ASSERT_TRUE(mstack->usr_extract_fd < 0);

                ASSERT_OK(mstack_open_images(
                                          mstack,
                                          /* mountfsd_link= */ NULL,
                                          /* userns_fd= */ -EBADF,
                                          /* image_policy= */ NULL,
                                          /* image_filter= */ NULL,
                                          /* flags= */ 0));

                _cleanup_(rmdir_and_freep) char *m = NULL;
                ASSERT_OK(mkdtemp_malloc("/tmp/mstack-temporary-XXXXXX", &m));

                ASSERT_OK(mstack_make_mounts(mstack, m, /* flags= */ 0, /* uid_shift= */ UID_INVALID));

                /* Now that the tree is fully assembled, /usr/ has actually been extracted, and
                 * root_mount_fd was replaced with a throwaway tmpfs. The consumed root/ entry must no
                 * longer be tracked as 'the' root - regression test for a real bug where a stale
                 * mstack->root_mount left mstack_bind_mounts() thinking there was still a real,
                 * to-be-protected root/ entry around, and it kept the fresh throwaway tmpfs read-only
                 * (mstack_has_writable_layers() is false for --volatile=yes, there being no rw/ layer),
                 * which broke every non-/usr/ write (e.g. base_filesystem_create()) immediately after. */
                ASSERT_TRUE(mstack->usr_extract_fd >= 0);
                ASSERT_TRUE(mstack->root_mount_fd >= 0);
                ASSERT_NULL(mstack->root_mount);

                _cleanup_(rmdir_and_freep) char *w = NULL;
                ASSERT_OK(mkdtemp_malloc("/tmp/mstack-where-XXXXXX", &w));

                _cleanup_close_ int rfd = -EBADF;
                ASSERT_OK(mstack_bind_mounts(mstack, w, /* where_fd= */ -EBADF, /* flags= */ 0, &rfd));

                /* The throwaway root must be writable, and /usr/ read-only underneath it. */
                ASSERT_OK_ZERO(path_is_read_only_fs(w));
                _cleanup_free_ char *usr = ASSERT_PTR(path_join(w, "usr"));
                ASSERT_OK_POSITIVE(path_is_read_only_fs(usr));

                /* And it must actually BE writable, not just report itself as such. */
                _cleanup_free_ char *probe = ASSERT_PTR(path_join(w, "probe"));
                ASSERT_OK_ERRNO(mkdir(probe, 0755));
        }

        /* --volatile=yes with neither a root/ entry nor any overlayfs content (no layer@/rw at all):
         * nothing to extract /usr/ from, refuse cleanly instead of guessing. */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-yes-empty-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));
                ASSERT_FALSE(mstack->root_mount);
                ASSERT_FALSE(mstack->has_overlayfs);

                ASSERT_EQ(mstack_merge_volatile(mstack, VOLATILE_YES, UID_INVALID, /* tmpfs_selinux_context= */ NULL), -EOPNOTSUPP);
        }
}

TEST(mstack_root_overlay_unification) {
        /* root/ folds into the same overlay as layer@/rw as its base (bottommost) layer whenever any
         * layers exist, instead of being mounted separately with only a /usr-only overlay submount on
         * top of it (see mstack_normalize()/mstack_make_overlayfs()). Structural check first: loading a
         * root/+layer@ mount stack must NOT demote the root/ entry into a plain bind mount - it stays a
         * real MSTACK_ROOT participant in the overlay. */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-root-unification-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                ASSERT_OK_ERRNO(mkdirat(tfd, "root", 0755));
                ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0", 0755));

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));

                ASSERT_TRUE(mstack->has_overlayfs);
                ASSERT_TRUE(mstack->root_mount);
                ASSERT_EQ(mstack->root_mount->mount_type, MSTACK_ROOT);
        }

        if (!have_effective_cap(CAP_SYS_ADMIN))
                return (void) log_tests_skipped("not attaching mstack, lacking privs");
        if (!mount_new_api_supported())
                return (void) log_tests_skipped("kernel does not support new mount API, skipping root/ unification test.");
        if (!overlayfs_lowerdir_plus_supported())
                return (void) log_tests_skipped("overlayfs does not support lowerdir+, skipping root/ unification test.");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("running in chroot(), skipping root/ unification test.");

        /* pidref_safe_fork() blocks further dlopen() in the child by default. The has_tmpfs_root blocks
         * below go through mstack_make_tmpfs() -> make_fsmount() -> mount_option_mangle(), which lazily
         * dlopen()s libmount; warm that up here in the parent first. Unlike TEST(mstack) above, this
         * can't rely on that TEST's own warm-up having already run first in the same process - systemd's
         * test framework doesn't guarantee TEST() execution follows declaration order. */
        {
                unsigned long mf;
                _cleanup_free_ char *mo = NULL;
                (void) mount_option_mangle("mode=0755", 0, &mf, &mo);
        }

        /* Full assembly: root/'s own content and layer@0's content must both be visible (merged across
         * the whole tree, not just /usr/), and a write outside /usr/ must land in rw/'s upperdir on the
         * host - not fail outright, and not silently mutate root/'s own source directory (the bug
         * c0e065d4fd fixed: previously root/ was forced read-only whenever the /usr-only split existed,
         * so writes outside /usr/ either failed, or - in configurations where root/ ended up writable -
         * mutated the root/ base image on the host directly instead of being captured in rw/). */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-root-unification-live-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                ASSERT_OK_ERRNO(mkdirat(tfd, "root", 0755));
                ASSERT_OK_ERRNO(mkdirat(tfd, "root/etc", 0755));
                _cleanup_close_ int root_etc_fd = openat(tfd, "root/etc", O_DIRECTORY|O_CLOEXEC);
                ASSERT_OK_ERRNO(root_etc_fd);
                _cleanup_close_ int root_marker_fd = openat(root_etc_fd, "root-marker", O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
                ASSERT_OK_ERRNO(root_marker_fd);
                root_marker_fd = safe_close(root_marker_fd);

                ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0", 0755));
                _cleanup_close_ int layer_fd = openat(tfd, "layer@0", O_DIRECTORY|O_CLOEXEC);
                ASSERT_OK_ERRNO(layer_fd);
                _cleanup_close_ int layer_marker_fd = openat(layer_fd, "layer-marker", O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
                ASSERT_OK_ERRNO(layer_marker_fd);
                layer_marker_fd = safe_close(layer_marker_fd);

                ASSERT_OK_ERRNO(mkdirat(tfd, "rw", 0755));

                int r = pidref_safe_fork("(mstack-root-unif)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, /* ret= */ NULL);
                ASSERT_OK(r);

                if (r == 0) {
                        tfd = safe_close(tfd);

                        _cleanup_(mstack_freep) MStack *mstack = NULL;
                        ASSERT_OK(mstack_load(t, -EBADF, &mstack));

                        ASSERT_OK(mstack_open_images(mstack, /* mountfsd_link= */ NULL, /* userns_fd= */ -EBADF,
                                                     /* image_policy= */ NULL, /* image_filter= */ NULL, /* flags= */ 0));

                        _cleanup_(rmdir_and_freep) char *m = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-temporary-XXXXXX", &m));
                        ASSERT_OK(mstack_make_mounts(mstack, m, /* flags= */ 0, /* uid_shift= */ UID_INVALID));

                        _cleanup_(rmdir_and_freep) char *w = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-where-XXXXXX", &w));

                        _cleanup_close_ int rfd = -EBADF;
                        ASSERT_OK(mstack_bind_mounts(mstack, w, /* where_fd= */ -EBADF, /* flags= */ 0, &rfd));

                        _cleanup_free_ char *root_marker = ASSERT_PTR(path_join(w, "etc/root-marker"));
                        ASSERT_OK_ERRNO(access(root_marker, F_OK));
                        _cleanup_free_ char *layer_marker = ASSERT_PTR(path_join(w, "layer-marker"));
                        ASSERT_OK_ERRNO(access(layer_marker, F_OK));

                        _cleanup_free_ char *new_file = ASSERT_PTR(path_join(w, "etc/new-file"));
                        _cleanup_close_ int new_fd = open(new_file, O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
                        ASSERT_OK_ERRNO(new_fd);
                        new_fd = safe_close(new_fd);

                        _exit(EXIT_SUCCESS);
                }

                /* The write above must have landed in rw/'s upperdir, not root/'s own source directory. */
                _cleanup_free_ char *host_new_file = ASSERT_PTR(path_join(t, "root/etc/new-file"));
                ASSERT_ERROR_ERRNO(access(host_new_file, F_OK), ENOENT);

                _cleanup_free_ char *upper_new_file = ASSERT_PTR(path_join(t, "rw/data/etc/new-file"));
                ASSERT_OK_ERRNO(access(upper_new_file, F_OK));
        }

        /* A throwaway tmpfs root (has_tmpfs_root, no real root/ entry backing it) has nothing to protect
         * and is never tied to an rw/ layer's writability, so it stays writable by default even without
         * any rw/ layer at all - only an explicit MSTACK_RDONLY should make it read-only. */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-tmpfs-root-writable-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                ASSERT_OK_ERRNO(mkdirat(tfd, "bind@somewhere", 0755));

                int r = pidref_safe_fork("(mstack-tmpfsroot)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, /* ret= */ NULL);
                ASSERT_OK(r);

                if (r == 0) {
                        tfd = safe_close(tfd);

                        _cleanup_(mstack_freep) MStack *mstack = NULL;
                        ASSERT_OK(mstack_load(t, -EBADF, &mstack));
                        ASSERT_TRUE(mstack->has_tmpfs_root);
                        ASSERT_FALSE(mstack->root_mount);

                        ASSERT_OK(mstack_open_images(mstack, /* mountfsd_link= */ NULL, /* userns_fd= */ -EBADF,
                                                     /* image_policy= */ NULL, /* image_filter= */ NULL, /* flags= */ 0));

                        _cleanup_(rmdir_and_freep) char *m = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-temporary-XXXXXX", &m));
                        ASSERT_OK(mstack_make_mounts(mstack, m, /* flags= */ 0, /* uid_shift= */ UID_INVALID));

                        _cleanup_(rmdir_and_freep) char *w = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-where-XXXXXX", &w));

                        _cleanup_close_ int rfd = -EBADF;
                        ASSERT_OK(mstack_bind_mounts(mstack, w, /* where_fd= */ -EBADF, /* flags= */ 0, &rfd));

                        ASSERT_OK_ZERO(path_is_read_only_fs(w));
                        _cleanup_free_ char *probe = ASSERT_PTR(path_join(w, "probe"));
                        ASSERT_OK_ERRNO(mkdir(probe, 0755));

                        _exit(EXIT_SUCCESS);
                }
        }

        /* has_tmpfs_root (e.g. bind@-only, no root/layer@/rw) merged with --volatile=overlay: a real bug
         * where mstack_normalize()'s single-layer collapse converted the synthetic, still-unbacked rw
         * layer into a MSTACK_BIND at "/" with no valid fd to bind-mount, breaking root resolution. The
         * synthetic layer must instead be dropped, falling back to has_tmpfs_root's own unconditional
         * fresh-tmpfs creation - the same end result the bind mount would have produced, once realized. */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-tmpfsroot-volatile-overlay-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                ASSERT_OK_ERRNO(mkdirat(tfd, "bind@somewhere", 0755));

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));
                ASSERT_TRUE(mstack->has_tmpfs_root);
                ASSERT_FALSE(mstack->root_mount);
                ASSERT_EQ(mstack->n_mounts, 1u); /* just bind@somewhere */

                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_OVERLAY, UID_INVALID, /* tmpfs_selinux_context= */ NULL));

                ASSERT_TRUE(mstack->has_tmpfs_root);
                ASSERT_FALSE(mstack->has_overlayfs);
                ASSERT_FALSE(mstack->root_mount);
                ASSERT_EQ(mstack->n_mounts, 1u); /* the synthetic rw layer was dropped, not left dangling */
                ASSERT_EQ(mstack->mounts[0].mount_type, MSTACK_BIND);

                if (!have_effective_cap(CAP_SYS_ADMIN))
                        return (void) log_tests_skipped("not attaching mstack, lacking privs");
                if (!mount_new_api_supported())
                        return (void) log_tests_skipped("kernel does not support new mount API, skipping has_tmpfs_root+overlay test.");
                if (running_in_chroot() > 0)
                        return (void) log_tests_skipped("running in chroot(), skipping has_tmpfs_root+overlay test.");

                /* mstack (loaded/merged above, in the parent's original mount namespace) isn't reused
                 * here - its bind@ entry's what_fd was opened before the fork, and later mount operations
                 * on it fail with EINVAL once inside the child's new mount namespace (FORK_NEW_MOUNTNS).
                 * Every other privileged test in this file avoids this by loading fresh inside the child;
                 * follow the same pattern. */
                mstack = mstack_free(mstack);

                int r = pidref_safe_fork("(mstack-tmpfsroot-vol)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, /* ret= */ NULL);
                ASSERT_OK(r);

                if (r == 0) {
                        tfd = safe_close(tfd);

                        ASSERT_OK(mstack_load(t, -EBADF, &mstack));
                        ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_OVERLAY, UID_INVALID, /* tmpfs_selinux_context= */ NULL));

                        ASSERT_OK(mstack_open_images(mstack, /* mountfsd_link= */ NULL, /* userns_fd= */ -EBADF,
                                                     /* image_policy= */ NULL, /* image_filter= */ NULL, /* flags= */ 0));

                        _cleanup_(rmdir_and_freep) char *m = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-temporary-XXXXXX", &m));
                        ASSERT_OK(mstack_make_mounts(mstack, m, /* flags= */ 0, /* uid_shift= */ UID_INVALID));

                        _cleanup_(rmdir_and_freep) char *w = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-where-XXXXXX", &w));

                        _cleanup_close_ int rfd = -EBADF;
                        ASSERT_OK(mstack_bind_mounts(mstack, w, /* where_fd= */ -EBADF, /* flags= */ 0, &rfd));

                        ASSERT_OK_ZERO(path_is_read_only_fs(w));
                        _cleanup_free_ char *probe = ASSERT_PTR(path_join(w, "probe"));
                        ASSERT_OK_ERRNO(mkdir(probe, 0755));

                        _exit(EXIT_SUCCESS);
                }
        }
}

TEST(mstack_volatile_yes_usr_merge_validation) {
        /* --volatile=yes validates that the assembled tree has adopted the merged-/usr scheme before
         * extracting /usr/ out of it: a real /bin/ directory (rather than a symlink into /usr/, or no
         * /bin/ at all) means /usr/ alone isn't enough to boot, and mstack_make_mounts() must refuse
         * cleanly instead of silently producing a broken (missing /bin, /sbin, /lib, /lib64) root. */
        if (!have_effective_cap(CAP_SYS_ADMIN))
                return (void) log_tests_skipped("not attaching mstack, lacking privs");
        if (!mount_new_api_supported())
                return (void) log_tests_skipped("kernel does not support new mount API, skipping usr-merge validation test.");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("running in chroot(), skipping usr-merge validation test.");

        /* /bin/ is a real, non-merged directory: refused with EISDIR. */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-yes-nonmerged-usr-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);
                ASSERT_OK_ERRNO(mkdirat(tfd, "usr", 0755));
                ASSERT_OK_ERRNO(mkdirat(tfd, "bin", 0755));

                int root_fd = open(t, O_PATH|O_DIRECTORY|O_CLOEXEC);
                ASSERT_OK_ERRNO(root_fd);

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_new_from_root_fd(TAKE_FD(root_fd), &mstack));
                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_YES, UID_INVALID, /* tmpfs_selinux_context= */ NULL));

                ASSERT_OK(mstack_open_images(mstack, /* mountfsd_link= */ NULL, /* userns_fd= */ -EBADF,
                                             /* image_policy= */ NULL, /* image_filter= */ NULL, /* flags= */ 0));

                _cleanup_(rmdir_and_freep) char *m = NULL;
                ASSERT_OK(mkdtemp_malloc("/tmp/mstack-temporary-XXXXXX", &m));

                ASSERT_EQ(mstack_make_mounts(mstack, m, /* flags= */ 0, /* uid_shift= */ UID_INVALID), -EISDIR);
        }

        /* /bin/ exists as neither a directory nor a symlink (a plain file): refused with EINVAL. */
        {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-yes-badbin-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);
                ASSERT_OK_ERRNO(mkdirat(tfd, "usr", 0755));
                _cleanup_close_ int bin_fd = openat(tfd, "bin", O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
                ASSERT_OK_ERRNO(bin_fd);
                bin_fd = safe_close(bin_fd);

                int root_fd = open(t, O_PATH|O_DIRECTORY|O_CLOEXEC);
                ASSERT_OK_ERRNO(root_fd);

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_new_from_root_fd(TAKE_FD(root_fd), &mstack));
                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_YES, UID_INVALID, /* tmpfs_selinux_context= */ NULL));

                ASSERT_OK(mstack_open_images(mstack, /* mountfsd_link= */ NULL, /* userns_fd= */ -EBADF,
                                             /* image_policy= */ NULL, /* image_filter= */ NULL, /* flags= */ 0));

                _cleanup_(rmdir_and_freep) char *m = NULL;
                ASSERT_OK(mkdtemp_malloc("/tmp/mstack-temporary-XXXXXX", &m));

                ASSERT_EQ(mstack_make_mounts(mstack, m, /* flags= */ 0, /* uid_shift= */ UID_INVALID), -EINVAL);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
