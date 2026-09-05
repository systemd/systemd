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
#include "volatile-util.h"

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

static int warm_up_libmount(void) {
        unsigned long flags;
        _cleanup_free_ char *options = NULL;

        /* pidref_safe_fork() blocks further dlopen() in the child by default. Realizing a tmpfs@ entry goes
         * through mstack_make_tmpfs() -> make_fsmount() -> mount_option_mangle(), which lazily dlopen()s
         * libmount; warm that up here in the parent (as real nspawn invocations already have, by the time
         * they get this far) so the child's call finds it already loaded instead of failing with EOPNOTSUPP.
         *
         * This doubles as a capability probe: in a build configured without libmount (--auto-features=disabled,
         * as CI's CLANG_ASAN_UBSAN_NO_DEPS phase does) mount_option_mangle() is a stub that fails with
         * EOPNOTSUPP for every non-empty option string, so no tmpfs@ entry can be realized there at all -
         * nothing the callers below can work around, hence they skip instead. */
        return mount_option_mangle("mode=0755", 0, &flags, &options);
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

        r = warm_up_libmount();
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped("libmount not available, cannot realize tmpfs@ mounts, skipping mstack attachment test.");
        ASSERT_OK(r);

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
        /* Some blocks below need a real detached mount to merge into, via open_tree(OPEN_TREE_CLONE),
         * which is privileged and part of the new mount API. Gate only those, so the purely structural
         * checks still run where neither is available - an unprivileged builder (rpmbuild, mock, a CI
         * container) would otherwise abort the whole test on the very first block. */
        bool can_mount = have_effective_cap(CAP_SYS_ADMIN) &&
                mount_new_api_supported() &&
                running_in_chroot() <= 0;
        if (!can_mount)
                log_info("Lacking privileges or the new mount API, skipping the blocks that need real mounts.");

        /* --volatile=overlay: existing root demoted to a lower layer, plus a synthetic rw upper. */
        if (can_mount) {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-overlay-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                /* mstack_new_from_root_fd() documents requiring a detached mount fd (e.g. from
                 * open_tree(..., OPEN_TREE_CLONE)), matching what real callers (nspawn.c's --directory=/ +
                 * --volatile= wrapping) always pass - a plain O_PATH fd on the directory itself doesn't
                 * qualify as a mount object for move_mount()-based operations further down. */
                int root_fd = open_tree(tfd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH);
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
        if (can_mount) {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-state-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);

                /* mstack_new_from_root_fd() documents requiring a detached mount fd (e.g. from
                 * open_tree(..., OPEN_TREE_CLONE)), matching what real callers (nspawn.c's --directory=/ +
                 * --volatile= wrapping) always pass - a plain O_PATH fd on the directory itself doesn't
                 * qualify as a mount object for move_mount()-based operations further down. */
                int root_fd = open_tree(tfd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH);
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

        if (!have_effective_cap(CAP_SYS_ADMIN))
                return (void) log_tests_skipped("not merging volatile=yes with a root/ entry, lacking privs");
        if (!mount_new_api_supported())
                return (void) log_tests_skipped("kernel does not support new mount API, skipping volatile=yes root/ merge test.");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("running in chroot(), skipping volatile=yes root/ merge test.");
        {
                /* --volatile=yes replaces root_mount_fd with a throwaway tmpfs, so this needs a realizable
                 * tmpfs just as much as the tmpfs@ tests do. No fork() here, so the warm-up aspect is moot -
                 * this is purely the capability probe. */
                int r = warm_up_libmount();
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return (void) log_tests_skipped("libmount not available, cannot realize the volatile=yes root tmpfs, skipping volatile=yes root/ merge test.");
                ASSERT_OK(r);
        }

        /* Like the other privileged blocks in this file, do the mount work in a throwaway mount
         * namespace: an assertion failing below would otherwise abort the process with the throwaway
         * root and its /usr/ submount still attached in the runner's own namespace, pinning the /tmp
         * directories and leaking into whatever runs next. Forking makes the cleanup unconditional. */
        int rr = pidref_safe_fork("(mstack-volatile-yes)",
                                  FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                                  /* ret= */ NULL);
        ASSERT_OK(rr);

        if (rr == 0) {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = mkdtemp_open("/tmp/mstack-volatile-yes-root-XXXXXX", O_PATH, &t);
                ASSERT_OK(tfd);
                ASSERT_OK_ERRNO(mkdirat(tfd, "usr", 0755));

                /* mstack_new_from_root_fd() documents requiring a detached mount fd (e.g. from
                 * open_tree(..., OPEN_TREE_CLONE)), matching what real callers (nspawn.c's --directory=/ +
                 * --volatile= wrapping) always pass - a plain O_PATH fd on the directory itself doesn't
                 * qualify as a mount object for move_mount()-based operations further down. */
                int root_fd = open_tree(tfd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH);
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

                _exit(EXIT_SUCCESS);
        }
}

TEST(mstack_symlinked_mount_target) {
        int r;

        /* Mount targets have to resolve through the image's own compatibility symlinks, with the
         * components below the symlink created past it. Following one must land the mount at the
         * resolved path - and, whatever the symlink says, must never land it outside the root. */

        if (!have_effective_cap(CAP_SYS_ADMIN))
                return (void) log_tests_skipped("not attaching mstack, lacking privs");
        if (!mount_new_api_supported())
                return (void) log_tests_skipped("kernel does not support new mount API, skipping symlinked mount target test.");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("running in chroot(), skipping symlinked mount target test.");

        r = pidref_safe_fork("(mstack-symlink-target)",
                             FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                             /* ret= */ NULL);
        ASSERT_OK(r);

        if (r == 0) {
                _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                _cleanup_close_ int tfd = -EBADF;
                tfd = ASSERT_FD(mkdtemp_open("/tmp/mstack-symlink-XXXXXX", O_PATH, &t));

                ASSERT_OK_ERRNO(mkdirat(tfd, "root", 0755));
                ASSERT_OK_ERRNO(mkdirat(tfd, "root/usr", 0755));
                ASSERT_OK_ERRNO(mkdirat(tfd, "root/run", 0755));
                ASSERT_OK_ERRNO(mkdirat(tfd, "root/var", 0755));
                ASSERT_OK_ERRNO(mkdirat(tfd, "root/etc", 0755));

                /* The image's own /var/run -> ../run, exactly as a merged-/usr image ships it. */
                ASSERT_OK_ERRNO(symlinkat("../run", tfd, "root/var/run"));

                /* And an absolute symlink that tries to point at the host's /etc/. Inside the container
                 * root that can only ever mean root/etc/, which is the guarantee being tested. */
                ASSERT_OK_ERRNO(symlinkat("/etc", tfd, "root/escape"));

                _cleanup_(rm_rf_physical_and_freep) char *deep_src = NULL;
                ASSERT_OK(mkdtemp_malloc("/tmp/mstack-symlink-deep-XXXXXX", &deep_src));
                _cleanup_free_ char *deep_marker = ASSERT_PTR(path_join(deep_src, "marker"));
                ASSERT_OK(write_string_file(deep_marker, "deep", WRITE_STRING_FILE_CREATE));

                _cleanup_(rm_rf_physical_and_freep) char *esc_src = NULL;
                ASSERT_OK(mkdtemp_malloc("/tmp/mstack-symlink-esc-XXXXXX", &esc_src));
                _cleanup_free_ char *esc_marker = ASSERT_PTR(path_join(esc_src, "marker"));
                ASSERT_OK(write_string_file(esc_marker, "escaped", WRITE_STRING_FILE_CREATE));

                /* A symlinked parent component, plus components below it that do not exist yet and so
                 * have to be created on the far side of the symlink. */
                _cleanup_free_ char *deep_entry = ASSERT_PTR(path_join(t, "robind@var-run-secrets-nested"));
                ASSERT_OK_ERRNO(symlink(deep_src, deep_entry));

                _cleanup_free_ char *esc_entry = ASSERT_PTR(path_join(t, "bind@escape"));
                ASSERT_OK_ERRNO(symlink(esc_src, esc_entry));

                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, /* dir_fd= */ -EBADF, &mstack));

                ASSERT_OK(mstack_open_images(mstack,
                                             /* mountfsd_link= */ NULL,
                                             /* userns_fd= */ -EBADF,
                                             /* image_policy= */ NULL,
                                             /* image_filter= */ NULL,
                                             /* flags= */ 0));

                _cleanup_(rmdir_and_freep) char *m = NULL;
                ASSERT_OK(mkdtemp_malloc("/tmp/mstack-symlink-tmp-XXXXXX", &m));
                ASSERT_OK(mstack_make_mounts(mstack, m, /* flags= */ 0, /* uid_shift= */ UID_INVALID));

                _cleanup_(rmdir_and_freep) char *w = NULL;
                ASSERT_OK(mkdtemp_malloc("/tmp/mstack-symlink-where-XXXXXX", &w));

                _cleanup_close_ int rfd = -EBADF;
                ASSERT_OK(mstack_bind_mounts(mstack, w, /* where_fd= */ -EBADF, /* flags= */ 0, &rfd));

                /* Reachable both by the name the entry used and by the resolved path, they being the
                 * same directory. */
                _cleanup_free_ char *via_var = ASSERT_PTR(path_join(w, "var/run/secrets/nested/marker"));
                _cleanup_free_ char *via_run = ASSERT_PTR(path_join(w, "run/secrets/nested/marker"));
                ASSERT_OK_POSITIVE(access(via_var, F_OK) >= 0);
                ASSERT_OK_POSITIVE(access(via_run, F_OK) >= 0);

                /* The absolute symlink resolved inside the root, not on the host. */
                _cleanup_free_ char *inside = ASSERT_PTR(path_join(w, "etc/marker"));
                ASSERT_OK_POSITIVE(access(inside, F_OK) >= 0);
                ASSERT_ERROR(RET_NERRNO(access("/etc/marker", F_OK)), ENOENT);

                _exit(EXIT_SUCCESS);
        }
}

TEST(mstack_usr_submount_attrs) {
        int r;

        /* mstack_apply_attr() deliberately does not pass AT_RECURSIVE for MSTACK_ROOT, so a /usr/ submount
         * keeps whatever attributes it was attached with instead of inheriting the root's. That is the
         * intended behaviour, but it means the root's writability and /usr/'s are decided independently -
         * so pin down both across the combinations that determine them: an rw/ layer (root writable) or
         * none (root read-only), against a robind@usr (always read-only) or a bind@usr (writable unless
         * either read-only flag applies). */

        if (!have_effective_cap(CAP_SYS_ADMIN))
                return (void) log_tests_skipped("not attaching mstack, lacking privs");
        if (!mount_new_api_supported())
                return (void) log_tests_skipped("kernel does not support new mount API, skipping /usr submount attribute test.");
        if (!overlayfs_lowerdir_plus_supported())
                return (void) log_tests_skipped("overlayfs does not support lowerdir+, skipping /usr submount attribute test.");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("running in chroot(), skipping /usr submount attribute test.");

        static const struct {
                const char *usr_entry;         /* the mount stack entry providing /usr/ */
                const char *usr_entry_content; /* mstack_load() ignores an empty entry directory */
                MStackFlags flags;
                bool expect_usr_ro;
        } cases[] = {
                /* robind@ is read-only by definition, bind@ only when the caller asks for it. Either way
                 * the answer must not depend on the root's own read-only state, which is what the
                 * non-recursive MSTACK_ROOT attribute pass is there to guarantee. */
                { "robind@usr", "robind@usr/from-usr", 0,                   true  },
                { "robind@usr", "robind@usr/from-usr", MSTACK_RDONLY,       true  },
                { "bind@usr",   "bind@usr/from-usr",   0,                   false },
                { "bind@usr",   "bind@usr/from-usr",   MSTACK_BINDS_RDONLY, true  },
                /* MSTACK_RDONLY covers the whole tree, binds included, without MSTACK_BINDS_RDONLY
                 * having to be set too: mstack_open_images() already attaches every entry read-only
                 * under it, and the attribute pass must not clear that again. */
                { "bind@usr",   "bind@usr/from-usr",   MSTACK_RDONLY,       true  },
        };

        FOREACH_ELEMENT(c, cases) {
                /* Each case attaches real mounts, so give it its own mount namespace - otherwise they
                 * would pile up in the test process and outlive the loop. */
                r = pidref_safe_fork("(mstack-usr-attrs)",
                                     FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                                     /* ret= */ NULL);
                ASSERT_OK(r);

                if (r == 0) {
                        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
                        _cleanup_close_ int tfd = -EBADF;
                        tfd = mkdtemp_open("/tmp/mstack-usr-attrs-XXXXXX", O_PATH, &t);
                        ASSERT_OK(tfd);

                        ASSERT_OK_ERRNO(mkdirat(tfd, "root", 0755));
                        ASSERT_OK_ERRNO(mkdirat(tfd, "root/usr", 0755));
                        ASSERT_OK_ERRNO(mkdirat(tfd, c->usr_entry, 0755));
                        ASSERT_OK_ERRNO(mkdirat(tfd, c->usr_entry_content, 0755));
                        /* Deliberately also offer overlay layers. A root/ plus a /usr bind is the classic
                         * root+/usr split rather than an overlay layout, so mstack_normalize() drops these
                         * (see the has_root && has_usr_bind case there) - which is exactly why the root can
                         * never be writable-via-rw/ in this shape, and why /usr/'s attributes have to stand
                         * on their own. Assert that, so the assumption is pinned rather than implied. */
                        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0", 0755));
                        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0/from-layer0", 0755));
                        ASSERT_OK_ERRNO(mkdirat(tfd, "rw", 0755));
                        ASSERT_OK_ERRNO(mkdirat(tfd, "rw/data", 0755));
                        ASSERT_OK_ERRNO(mkdirat(tfd, "rw/data/from-rw", 0755));
                        ASSERT_OK_ERRNO(mkdirat(tfd, "rw/work", 0755));

                        _cleanup_(mstack_freep) MStack *mstack = NULL;
                        ASSERT_OK(mstack_load(t, /* dir_fd= */ -EBADF, &mstack));
                        FOREACH_ARRAY(mm, mstack->mounts, mstack->n_mounts)
                                ASSERT_FALSE(IN_SET(mm->mount_type, MSTACK_LAYER, MSTACK_RW));
                        ASSERT_FALSE(mstack->has_overlayfs);

                        ASSERT_OK(mstack_open_images(mstack,
                                                     /* mountfsd_link= */ NULL,
                                                     /* userns_fd= */ -EBADF,
                                                     /* image_policy= */ NULL,
                                                     /* image_filter= */ NULL,
                                                     c->flags));

                        _cleanup_(rmdir_and_freep) char *m = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-usr-attrs-tmp-XXXXXX", &m));
                        ASSERT_OK(mstack_make_mounts(mstack, m, c->flags, /* uid_shift= */ UID_INVALID));

                        _cleanup_(rmdir_and_freep) char *w = NULL;
                        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-usr-attrs-where-XXXXXX", &w));

                        _cleanup_close_ int rfd = -EBADF;
                        ASSERT_OK(mstack_bind_mounts(mstack, w, /* where_fd= */ -EBADF, c->flags, &rfd));

                        _cleanup_free_ char *usr = ASSERT_PTR(path_join(w, "usr"));

                        log_info("%s flags=%u: root_ro=%i usr_ro=%i",
                                 c->usr_entry, c->flags,
                                 path_is_read_only_fs(w), path_is_read_only_fs(usr));

                        /* The root has no writable layer left in this shape, so it is read-only throughout. */
                        ASSERT_OK_POSITIVE(path_is_read_only_fs(w));

                        if (c->expect_usr_ro)
                                ASSERT_OK_POSITIVE(path_is_read_only_fs(usr));
                        else
                                ASSERT_OK_ZERO(path_is_read_only_fs(usr));

                        _exit(EXIT_SUCCESS);
                }
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

        /* Unlike TEST(mstack) above, this can't rely on that TEST's own warm-up having already run first in
         * the same process - systemd's test framework doesn't guarantee TEST() execution follows
         * declaration order. */
        {
                int r = warm_up_libmount();
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return (void) log_tests_skipped("libmount not available, cannot realize tmpfs@ mounts, skipping root/ unification test.");
                ASSERT_OK(r);
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

                /* mstack_new_from_root_fd() documents requiring a detached mount fd (e.g. from
                 * open_tree(..., OPEN_TREE_CLONE)), matching what real callers (nspawn.c's --directory=/ +
                 * --volatile= wrapping) always pass - a plain O_PATH fd on the directory itself doesn't
                 * qualify as a mount object for move_mount()-based operations further down. */
                int root_fd = open_tree(tfd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH);
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

                /* mstack_new_from_root_fd() documents requiring a detached mount fd (e.g. from
                 * open_tree(..., OPEN_TREE_CLONE)), matching what real callers (nspawn.c's --directory=/ +
                 * --volatile= wrapping) always pass - a plain O_PATH fd on the directory itself doesn't
                 * qualify as a mount object for move_mount()-based operations further down. */
                int root_fd = open_tree(tfd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH);
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

/* The plan is worked out before anything is mounted, so all of this runs with no privileges at all -
 * which matters, because it is where the decisions live and the blocks that need real mounts skip on an
 * unprivileged builder. */

static const MStackLayerPlan* plan_find(const MStackPlan *plan, MStackMountType type) {
        ASSERT_NOT_NULL(plan);

        FOREACH_ARRAY(l, plan->layers, plan->n_layers)
                if (l->mount->mount_type == type)
                        return l;

        return NULL;
}

TEST(mstack_plan_shape) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        tfd = mkdtemp_open("/tmp/mstack-plan-XXXXXX", O_PATH, &t);
        ASSERT_OK(tfd);

        /* A lone root/ is bound as-is: no overlay, and nothing to attach, so no child. */
        ASSERT_OK_ERRNO(mkdirat(tfd, "root", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "root/usr", 0755));
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, /* uid_shift= */ UID_INVALID, &plan));

                ASSERT_EQ(plan->shape, MSTACK_ROOT_SHAPE_BIND);
                ASSERT_FALSE(plan->idmap_root_directly);
                ASSERT_FALSE(plan->extract_usr);
        }

        /* Same shape, but with a uid_shift the root is idmapped where it stands rather than by way of
         * the overlay - the two are mutually exclusive, and only the non-overlay shapes can do it. */
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, 1310720, &plan));

                ASSERT_EQ(plan->shape, MSTACK_ROOT_SHAPE_BIND);
                ASSERT_TRUE(plan->idmap_root_directly);
                ASSERT_EQ(plan->root_uid_shift, 1310720u);
        }

        /* Add a layer@ and the root becomes the overlay's base instead. */
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0/marker", 0755));
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, /* uid_shift= */ UID_INVALID, &plan));

                ASSERT_EQ(plan->shape, MSTACK_ROOT_SHAPE_OVERLAY);
                ASSERT_EQ(plan->n_layers, 2u);
                ASSERT_EQ(ASSERT_PTR(plan_find(plan, MSTACK_ROOT))->role, MSTACK_LAYER_ROLE_LOWER);
                ASSERT_EQ(ASSERT_PTR(plan_find(plan, MSTACK_LAYER))->role, MSTACK_LAYER_ROLE_LOWER);

                /* No writable layer, hence no upper. */
                ASSERT_NULL((void*) plan_find(plan, MSTACK_RW));
        }
}

TEST(mstack_plan_roles_and_identity) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        tfd = mkdtemp_open("/tmp/mstack-plan-id-XXXXXX", O_PATH, &t);
        ASSERT_OK(tfd);

        ASSERT_OK_ERRNO(mkdirat(tfd, "root", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "root/usr", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "layer@0/marker", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "rw", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "rw/data", 0755));

        /* Writable rw/ is the upper, and it is what makes a mount namespace child necessary. */
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, /* uid_shift= */ UID_INVALID, &plan));

                ASSERT_EQ(ASSERT_PTR(plan_find(plan, MSTACK_RW))->role, MSTACK_LAYER_ROLE_UPPER);
                ASSERT_EQ(ASSERT_PTR(plan_find(plan, MSTACK_LAYER))->role, MSTACK_LAYER_ROLE_LOWER);
        }

        /* MSTACK_RDONLY demotes it to just another lower. */
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, MSTACK_RDONLY, /* uid_shift= */ UID_INVALID, &plan));

                ASSERT_EQ(ASSERT_PTR(plan_find(plan, MSTACK_RW))->role, MSTACK_LAYER_ROLE_LOWER);
        }

        /* An idmap shifts the read-only layers and never the writable one - that asymmetry is the whole
         * point of mstack_layer_identity(), and getting it wrong either way is a bug this has had. */
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, 1310720, &plan));

                ASSERT_EQ(ASSERT_PTR(plan_find(plan, MSTACK_LAYER))->identity, MSTACK_LAYER_IDENTITY_IDMAP);
                ASSERT_EQ(ASSERT_PTR(plan_find(plan, MSTACK_ROOT))->identity, MSTACK_LAYER_IDENTITY_IDMAP);

                /* uid_shift alone says only that the layers are idmapped; without tmpfs_uid_shift the
                 * payload still runs as real root, so the upper is left alone. */
                ASSERT_EQ(ASSERT_PTR(plan_find(plan, MSTACK_RW))->identity, MSTACK_LAYER_IDENTITY_NONE);
        }

        /* Once the caller says the payload runs shifted, the upper is chowned to it instead. */
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));
                mstack->tmpfs_uid_shift = 1310720;

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, 1310720, &plan));

                const MStackLayerPlan *upper = ASSERT_PTR(plan_find(plan, MSTACK_RW));
                ASSERT_EQ(upper->identity, MSTACK_LAYER_IDENTITY_CHOWN);
                ASSERT_EQ(upper->identity_uid, 1310720u);

                /* And still never an idmap on the writable layer, which silently mounts it read-only. */
                ASSERT_NE(upper->identity, MSTACK_LAYER_IDENTITY_IDMAP);
        }
}

TEST(mstack_plan_after_merge_volatile) {
        /* The shape this PR exists to get right is the one a stack has *after* --volatile= has been
         * merged into it, and mstack_plan() is the one place that answers it without needing a single
         * privilege - so pin it down here rather than only end to end, where CAP_SYS_ADMIN and a
         * cooperative overlayfs decide whether the check runs at all. */

        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        tfd = mkdtemp_open("/tmp/mstack-plan-vol-XXXXXX", O_PATH, &t);
        ASSERT_OK(tfd);

        ASSERT_OK_ERRNO(mkdirat(tfd, "root", 0755));
        ASSERT_OK_ERRNO(mkdirat(tfd, "root/usr", 0755));

        /* --volatile=overlay demotes root/ to a lower layer and conjures a writable upper that has no
         * backing on disk yet - which is exactly what the UPPER_UNBACKED role is there to remember. */
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));
                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_OVERLAY,
                                                /* tmpfs_uid_shift= */ UID_INVALID,
                                                /* tmpfs_selinux_context= */ NULL));

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, /* uid_shift= */ UID_INVALID, &plan));

                ASSERT_EQ(plan->shape, MSTACK_ROOT_SHAPE_OVERLAY);
                ASSERT_FALSE(plan->idmap_root_directly);

                const MStackLayerPlan *upper = ASSERT_PTR(plan_find(plan, MSTACK_RW));
                ASSERT_EQ(upper->role, MSTACK_LAYER_ROLE_UPPER_UNBACKED);
                ASSERT_TRUE(mstack_layer_role_is_upper(upper->role));

                /* The former root/ is now just the bottom lower, and brings its own backing. */
                const MStackLayerPlan *lower = ASSERT_PTR(plan_find(plan, MSTACK_LAYER));
                ASSERT_EQ(lower->role, MSTACK_LAYER_ROLE_LOWER);
                ASSERT_FALSE(mstack_layer_role_is_upper(lower->role));
        }

        /* --volatile=state leaves the root alone and adds an overmount, not a layer: the plan covers
         * layers only, so the stack still plans as a lone bound root. */
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));
                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_STATE,
                                                /* tmpfs_uid_shift= */ UID_INVALID,
                                                /* tmpfs_selinux_context= */ NULL));

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, /* uid_shift= */ UID_INVALID, &plan));

                ASSERT_EQ(plan->shape, MSTACK_ROOT_SHAPE_BIND);
                ASSERT_FALSE(plan->extract_usr);
                ASSERT_NULL((void*) plan_find(plan, MSTACK_RW));
                ASSERT_NULL((void*) plan_find(plan, MSTACK_TMPFS));
        }

        /* --volatile=yes defers the /usr/ extraction to assembly, and says so in the plan. */
        {
                _cleanup_(mstack_freep) MStack *mstack = NULL;
                ASSERT_OK(mstack_load(t, tfd, &mstack));
                ASSERT_OK(mstack_merge_volatile(mstack, VOLATILE_YES,
                                                /* tmpfs_uid_shift= */ UID_INVALID,
                                                /* tmpfs_selinux_context= */ NULL));

                _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
                ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, /* uid_shift= */ UID_INVALID, &plan));

                ASSERT_TRUE(plan->extract_usr);
        }
}

TEST(mstack_plan_tmpfs_root_shape) {
        /* A stack with nothing persistent underneath gets a throwaway tmpfs for a root. Worth a
         * plan-level check of its own: this is the shape that combined with --volatile=overlay was a
         * real bug, and everything else that covers it needs privileges. */

        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        tfd = mkdtemp_open("/tmp/mstack-plan-tmpfsroot-XXXXXX", O_PATH, &t);
        ASSERT_OK(tfd);

        _cleanup_(rm_rf_physical_and_freep) char *src = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/mstack-plan-bindsrc-XXXXXX", &src));

        _cleanup_free_ char *link = ASSERT_PTR(path_join(t, "bind@srv"));
        ASSERT_OK_ERRNO(symlink(src, link));

        _cleanup_(mstack_freep) MStack *mstack = NULL;
        ASSERT_OK(mstack_load(t, tfd, &mstack));
        ASSERT_TRUE(mstack->has_tmpfs_root);

        _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
        ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, /* uid_shift= */ UID_INVALID, &plan));

        ASSERT_EQ(plan->shape, MSTACK_ROOT_SHAPE_TMPFS);
        ASSERT_EQ(plan->n_layers, 0u);

        /* A tmpfs root is not an overlay, so it too is idmapped directly when a shift is asked for. */
        _cleanup_(mstack_plan_freep) MStackPlan *shifted = NULL;
        ASSERT_OK(mstack_plan(mstack, /* flags= */ 0, 1310720, &shifted));
        ASSERT_EQ(shifted->shape, MSTACK_ROOT_SHAPE_TMPFS);
        ASSERT_TRUE(shifted->idmap_root_directly);
}

DEFINE_TEST_MAIN(LOG_INFO);
