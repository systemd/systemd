/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "libmount-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "virt.h"

#define FORK_COMMON_FLAGS                       \
        (FORK_CLOSE_ALL_FDS |                   \
         FORK_RESET_SIGNALS |                   \
         FORK_DEATHSIG_SIGTERM |                \
         FORK_LOG |                             \
         FORK_REOPEN_LOG |                      \
         FORK_WAIT |                            \
         FORK_NEW_MOUNTNS |                     \
         FORK_MOUNTNS_SLAVE)

#define CHECK_PRIV                                                      \
        if (geteuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)   \
                return (void) log_tests_skipped("Not privileged");      \
        if (running_in_chroot() != 0)                                   \
                return (void) log_tests_skipped("running in chroot");

/* Only a probe verdict of -EOPNOTSUPP may skip the kernel-table pass; any other probe error must
 * fail the test loudly rather than silently shrink its coverage. */
#define SKIP_UNLESS_KERNEL_TABLE(backend, have_kernel)                                             \
        if (streq(backend, "1")) {                                                                 \
                if ((have_kernel) == -EOPNOTSUPP) {                                                \
                        log_notice("listmount()/statmount() are not available, skipping the kernel-table pass."); \
                        continue;                                                                  \
                }                                                                                  \
                ASSERT_OK(have_kernel);                                                            \
        }

/* Whether libmount_parse_kernel() can deliver a table here. $SYSTEMD_LISTMOUNT=1 only means "do
 * not force the mountinfo fallback": when the kernel or the runtime libmount lacks the syscalls,
 * a pass run under it degrades to the mountinfo path and passes without touching the code it was
 * meant to cover. The per-backend loops below probe this first and skip that pass visibly, but
 * only on -EOPNOTSUPP: any other error is unexpected and must fail the test rather than shrink
 * it. An ambient $SYSTEMD_LISTMOUNT=0 also reads as -EOPNOTSUPP, by design: that is the
 * documented opt-out, and it takes the same visible-skip path. */
static int have_kernel_mount_table(void) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;

        return libmount_parse_kernel(STATMOUNT_MNT_POINT, MNT_ITER_FORWARD, &table, &iter);
}

TEST(mount_option_mangle) {
        char *opts = NULL;
        unsigned long f;

        assert_se(mount_option_mangle(NULL, MS_RDONLY|MS_NOSUID, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID));
        ASSERT_NULL(opts);

        assert_se(mount_option_mangle("", MS_RDONLY|MS_NOSUID, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID));
        ASSERT_NULL(opts);

        assert_se(mount_option_mangle("ro,nosuid,nodev,noexec", 0, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        ASSERT_NULL(opts);

        assert_se(mount_option_mangle("ro,nosuid,nodev,noexec,mode=0755", 0, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        ASSERT_STREQ(opts, "mode=0755");
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,foo,hogehoge,nodev,mode=0755", 0, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV));
        ASSERT_STREQ(opts, "foo,hogehoge,mode=0755");
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,nodev,noexec,relatime,net_cls,net_prio", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME));
        ASSERT_STREQ(opts, "net_cls,net_prio");
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,nodev,relatime,size=1630748k,mode=0700,uid=1000,gid=1000", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_RELATIME));
        ASSERT_STREQ(opts, "size=1630748k,mode=0700,uid=1000,gid=1000");
        opts = mfree(opts);

        assert_se(mount_option_mangle("size=1630748k,rw,gid=1000,,,nodev,relatime,,mode=0700,nosuid,uid=1000", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_RELATIME));
        ASSERT_STREQ(opts, "size=1630748k,gid=1000,mode=0700,uid=1000");
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,exec,size=8143984k,nr_inodes=2035996,mode=0755", MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV));
        ASSERT_STREQ(opts, "size=8143984k,nr_inodes=2035996,mode=0755");
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,relatime,fmask=0022,,,dmask=0022", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == MS_RELATIME);
        ASSERT_STREQ(opts, "fmask=0022,dmask=0022");
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,relatime,fmask=0022,dmask=0022,\"hogehoge", MS_RDONLY, &f, &opts) < 0);

        assert_se(mount_option_mangle("mode=01777,size=10%,nr_inodes=400k,uid=496107520,gid=496107520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"", 0, &f, &opts) == 0);
        assert_se(f == 0);
        ASSERT_STREQ(opts, "mode=01777,size=10%,nr_inodes=400k,uid=496107520,gid=496107520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"");
        opts = mfree(opts);
}

static void test_mount_flags_to_string_one(unsigned long flags, const char *expected) {
        _cleanup_free_ char *x = NULL;
        int r;

        r = mount_flags_to_string(flags, &x);
        log_info("flags: %#lX → %d/\"%s\"", flags, r, strnull(x));
        assert_se(r >= 0);
        ASSERT_STREQ(x, expected);
}

TEST(mount_flags_to_string) {
        test_mount_flags_to_string_one(0, "0");
        test_mount_flags_to_string_one(MS_RDONLY, "MS_RDONLY");
        test_mount_flags_to_string_one(MS_NOSUID, "MS_NOSUID");
        test_mount_flags_to_string_one(MS_NODEV, "MS_NODEV");
        test_mount_flags_to_string_one(MS_NOEXEC, "MS_NOEXEC");
        test_mount_flags_to_string_one(MS_SYNCHRONOUS, "MS_SYNCHRONOUS");
        test_mount_flags_to_string_one(MS_REMOUNT, "MS_REMOUNT");
        test_mount_flags_to_string_one(MS_MANDLOCK, "MS_MANDLOCK");
        test_mount_flags_to_string_one(MS_DIRSYNC, "MS_DIRSYNC");
        test_mount_flags_to_string_one(MS_NOSYMFOLLOW, "MS_NOSYMFOLLOW");
        test_mount_flags_to_string_one(MS_NOATIME, "MS_NOATIME");
        test_mount_flags_to_string_one(MS_NODIRATIME, "MS_NODIRATIME");
        test_mount_flags_to_string_one(MS_BIND, "MS_BIND");
        test_mount_flags_to_string_one(MS_MOVE, "MS_MOVE");
        test_mount_flags_to_string_one(MS_REC, "MS_REC");
        test_mount_flags_to_string_one(MS_SILENT, "MS_SILENT");
        test_mount_flags_to_string_one(MS_POSIXACL, "MS_POSIXACL");
        test_mount_flags_to_string_one(MS_UNBINDABLE, "MS_UNBINDABLE");
        test_mount_flags_to_string_one(MS_PRIVATE, "MS_PRIVATE");
        test_mount_flags_to_string_one(MS_SLAVE, "MS_SLAVE");
        test_mount_flags_to_string_one(MS_SHARED, "MS_SHARED");
        test_mount_flags_to_string_one(MS_RELATIME, "MS_RELATIME");
        test_mount_flags_to_string_one(MS_KERNMOUNT, "MS_KERNMOUNT");
        test_mount_flags_to_string_one(MS_I_VERSION, "MS_I_VERSION");
        test_mount_flags_to_string_one(MS_STRICTATIME, "MS_STRICTATIME");
        test_mount_flags_to_string_one(MS_LAZYTIME, "MS_LAZYTIME");
        test_mount_flags_to_string_one(MS_LAZYTIME|MS_STRICTATIME, "MS_STRICTATIME|MS_LAZYTIME");
        test_mount_flags_to_string_one(UINT_MAX,
                                       "MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_SYNCHRONOUS|MS_REMOUNT|"
                                       "MS_MANDLOCK|MS_DIRSYNC|MS_NOSYMFOLLOW|MS_NOATIME|MS_NODIRATIME|"
                                       "MS_BIND|MS_MOVE|MS_REC|MS_SILENT|MS_POSIXACL|MS_UNBINDABLE|"
                                       "MS_PRIVATE|MS_SLAVE|MS_SHARED|MS_RELATIME|MS_KERNMOUNT|"
                                       "MS_I_VERSION|MS_STRICTATIME|MS_LAZYTIME|fc000200");
}

TEST(bind_remount_recursive) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *subdir = NULL;
        int r;

        CHECK_PRIV;

        int have_kernel = have_kernel_mount_table();

        assert_se(mkdtemp_malloc("/tmp/XXXXXX", &tmp) >= 0);
        subdir = path_join(tmp, "subdir");
        assert_se(subdir);
        assert_se(mkdir(subdir, 0755) >= 0);

        /* Each child runs once through listmount()/statmount() where the kernel has them, and once
         * forced onto the mountinfo fallback; the variable only ever reaches the forked child. */
        FOREACH_STRING(backend, "1", "0") {
                SKIP_UNLESS_KERNEL_TABLE(backend, have_kernel);

                FOREACH_STRING(p, "/usr", "/sys", "/", tmp) {
                        r = ASSERT_OK(pidref_safe_fork("(bind-remount-recursive)", FORK_COMMON_FLAGS, NULL));
                        if (r == 0) { /* child */
                                struct statvfs svfs;

                                ASSERT_OK_ERRNO(setenv("SYSTEMD_LISTMOUNT", backend, /* overwrite= */ true));

                                /* Check that the subdir is writable (it must be because it's in /tmp) */
                                assert_se(statvfs(subdir, &svfs) >= 0);
                                assert_se(!FLAGS_SET(svfs.f_flag, ST_RDONLY));

                                /* Make the subdir a bind mount carrying nosuid, so there is a flag
                                 * outside the mask below whose survival can be checked */
                                assert_se(mount_nofollow(subdir, subdir, NULL, MS_BIND|MS_REC, NULL) >= 0);
                                assert_se(mount_nofollow(NULL, subdir, NULL, MS_BIND|MS_REMOUNT|MS_NOSUID, NULL) >= 0);

                                /* Ensure it's still writable */
                                assert_se(statvfs(subdir, &svfs) >= 0);
                                assert_se(!FLAGS_SET(svfs.f_flag, ST_RDONLY));

                                /* Now mark the path we currently run for read-only. For the private
                                 * tmpdir the mask carries a bit mount_setattr() cannot express, so
                                 * that prefix skips the shortcut and reapplies each mount's
                                 * looked-up flags through the enumerated table under both
                                 * backends; the other prefixes keep covering the shortcut. */
                                assert_se(bind_remount_recursive(p, MS_RDONLY,
                                                                 MS_RDONLY | (path_equal(p, tmp) ? MS_SYNCHRONOUS : 0),
                                                                 path_equal(p, "/sys") ? STRV_MAKE("/sys/kernel") : NULL) >= 0);

                                /* Ensure that this worked on the top-level */
                                assert_se(statvfs(p, &svfs) >= 0);
                                assert_se(FLAGS_SET(svfs.f_flag, ST_RDONLY));

                                /* And ensure this had an effect on the subdir exactly if we are talking about a path above the subdir */
                                assert_se(statvfs(subdir, &svfs) >= 0);
                                assert_se(FLAGS_SET(svfs.f_flag, ST_RDONLY) == !!path_startswith(subdir, p));

                                /* The table path must have preserved the nosuid outside its mask */
                                if (path_equal(p, tmp))
                                        assert_se(FLAGS_SET(svfs.f_flag, ST_NOSUID));

                                _exit(EXIT_SUCCESS);
                        }
                }
        }
}

TEST(bind_remount_one) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        int r;

        CHECK_PRIV;

        int have_kernel = have_kernel_mount_table();

        ASSERT_OK(mkdtemp_malloc(NULL, &t));

        /* As above: one pass per backend, decided in the forked child. The mount-point cases with
         * a convertible mask return through the mount_setattr() shortcut; the tmpfs case's mask
         * carries a bit mount_setattr() cannot express, so it is the one that reaches the mount
         * table lookup on a path that is actually a mount, and the flags outside the mask must
         * come back out of the table: the remount may not strip the tmpfs's nosuid/nodev. */
        FOREACH_STRING(backend, "1", "0") {
                SKIP_UNLESS_KERNEL_TABLE(backend, have_kernel);

                r = ASSERT_OK(pidref_safe_fork("(remount-one-with-mountinfo)", FORK_COMMON_FLAGS, NULL));
                if (r == 0) { /* child */
                        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
                        struct statvfs svfs;

                        ASSERT_OK_ERRNO(setenv("SYSTEMD_LISTMOUNT", backend, /* overwrite= */ true));

                        assert_se(fopen_unlocked("/proc/self/mountinfo", "re", &proc_self_mountinfo) >= 0);

                        assert_se(bind_remount_one_with_mountinfo("/run", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) >= 0);
                        assert_se(bind_remount_one_with_mountinfo("/run", MS_NOEXEC, MS_RDONLY|MS_NOEXEC, proc_self_mountinfo) >= 0);
                        assert_se(bind_remount_one_with_mountinfo("/proc/idontexist", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) == -ENOENT);
                        assert_se(bind_remount_one_with_mountinfo("/proc/self", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) == -EINVAL);
                        assert_se(bind_remount_one_with_mountinfo("/", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) >= 0);

                        ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", t, "tmpfs", MS_NOSUID|MS_NODEV, NULL));
                        ASSERT_OK(bind_remount_one_with_mountinfo(t, MS_RDONLY, MS_RDONLY|MS_SYNCHRONOUS, proc_self_mountinfo));
                        ASSERT_OK_ERRNO(statvfs(t, &svfs));
                        ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_RDONLY));
                        ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_NOSUID));
                        ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_NODEV));

                        _exit(EXIT_SUCCESS);
                }

                r = ASSERT_OK(pidref_safe_fork("(remount-one)", FORK_COMMON_FLAGS, NULL));
                if (r == 0) { /* child */
                        struct statvfs svfs;

                        ASSERT_OK_ERRNO(setenv("SYSTEMD_LISTMOUNT", backend, /* overwrite= */ true));

                        assert_se(bind_remount_one("/run", MS_RDONLY, MS_RDONLY) >= 0);
                        assert_se(bind_remount_one("/run", MS_NOEXEC, MS_RDONLY|MS_NOEXEC) >= 0);
                        assert_se(bind_remount_one("/proc/idontexist", MS_RDONLY, MS_RDONLY) == -ENOENT);
                        assert_se(bind_remount_one("/proc/self", MS_RDONLY, MS_RDONLY) == -EINVAL);
                        assert_se(bind_remount_one("/", MS_RDONLY, MS_RDONLY) >= 0);

                        ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", t, "tmpfs", MS_NOSUID|MS_NODEV, NULL));
                        ASSERT_OK(bind_remount_one(t, MS_RDONLY, MS_RDONLY|MS_SYNCHRONOUS));
                        ASSERT_OK_ERRNO(statvfs(t, &svfs));
                        ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_RDONLY));
                        ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_NOSUID));
                        ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_NODEV));

                        _exit(EXIT_SUCCESS);
                }
        }
}

TEST(bind_remount_one_nonexistent) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        int r;

        /* A path that is not there at all must report -ENOENT rather than -EINVAL, which is
         * reserved for "exists but is not a mount point". namespace.c drops an entry marked
         * ignorable on the first and fails namespace setup on the second. Passing no mountinfo
         * stream also covers the kernel-only enumeration path, where the mount table lookup and
         * the existence check come from different places. */

        ASSERT_ERROR(bind_remount_one_with_mountinfo("/run/test-mount-util-does-not-exist", MS_RDONLY, MS_RDONLY, NULL), ENOENT);

        /* The -EINVAL half needs a backend that can say no table lists the path: the kernel
         * table concludes it here, and without one the kernel path's -EOPNOTSUPP comes through
         * instead, since there is nothing to consult. */
        ASSERT_OK(mkdtemp_malloc("/tmp/test-mount-util.XXXXXX", &t));
        r = bind_remount_one_with_mountinfo(t, MS_RDONLY, MS_RDONLY, NULL);
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("listmount()/statmount() are not available");
        ASSERT_ERROR(r, EINVAL);
}

TEST(remount_and_umount_with_proc_masked) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_free_ char *subdir = NULL;
        int r;

        /* Namespace setup no longer requires /proc/self/mountinfo. What is checkable under a
         * masked /proc splits three ways: a recursive read-only remount still works where
         * mount_setattr() can express it; umount_recursive() still works outright, since its
         * enumeration comes from the kernel table and umount2() takes a plain path; and when
         * $SYSTEMD_LISTMOUNT=0 leaves no backend at all, both fail rather than skip their work
         * silently. The classic per-mount remount is not reachable without /proc whatever built
         * the table: mount_fd() addresses the mount target through /proc/self/fd/ and reports
         * ENOSYS when /proc is not there. */

        CHECK_PRIV;

        r = have_kernel_mount_table();
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("listmount()/statmount() are not available");
        ASSERT_OK(r);

        ASSERT_OK(mkdtemp_malloc(NULL, &t));
        ASSERT_NOT_NULL(subdir = path_join(t, "subdir"));

        r = ASSERT_OK(pidref_safe_fork("(proc-masked)", FORK_COMMON_FLAGS, NULL));
        if (r == 0) { /* child */
                struct statvfs svfs;

                ASSERT_OK_ERRNO(setenv("SYSTEMD_LISTMOUNT", "1", /* overwrite= */ true));

                ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", t, "tmpfs", 0, NULL));
                ASSERT_OK_ERRNO(mkdir(subdir, 0755));
                /* noexec is the canary the parent lacks: as long as statvfs(subdir) reports it,
                 * the subdir mount is still there and the flags below really are the subdir's,
                 * not the identically read-only parent's showing through after a detach. */
                ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", subdir, "tmpfs", MS_NOEXEC, NULL));

                /* Mask /proc, as InaccessiblePaths=/proc would */
                ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", "/proc", "tmpfs", 0, NULL));
                ASSERT_LT(access("/proc/self/mountinfo", F_OK), 0);

                ASSERT_OK(bind_remount_recursive(t, MS_RDONLY, MS_RDONLY, NULL));
                ASSERT_OK_ERRNO(statvfs(t, &svfs));
                ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_RDONLY));
                ASSERT_OK_ERRNO(statvfs(subdir, &svfs));
                ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_RDONLY));
                ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_NOEXEC));

                /* No kernel table and no /proc: fail-closed, and the tree is untouched. The
                 * remount mask carries a bit mount_setattr() cannot express, so the shortcut
                 * cannot answer for it and enumeration itself has to fail. ST_RDONLY alone
                 * cannot show the tree is untouched: had the failed umount detached subdir,
                 * statvfs() would read the parent, which is just as read-only. The noexec
                 * canary only exists on the subdir mount, so it pins the read to it. */
                ASSERT_OK_ERRNO(setenv("SYSTEMD_LISTMOUNT", "0", /* overwrite= */ true));
                ASSERT_ERROR(bind_remount_recursive(t, MS_RDONLY, MS_RDONLY|MS_SYNCHRONOUS, NULL), EOPNOTSUPP);
                ASSERT_ERROR(umount_recursive(t, MNT_DETACH), EOPNOTSUPP);
                ASSERT_OK_ERRNO(statvfs(subdir, &svfs));
                ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_RDONLY));
                ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_NOEXEC));

                /* The kernel table alone must carry the whole umount */
                ASSERT_OK_ERRNO(setenv("SYSTEMD_LISTMOUNT", "1", /* overwrite= */ true));
                ASSERT_OK(umount_recursive(t, MNT_DETACH));
                ASSERT_OK_ERRNO(statvfs(t, &svfs));
                ASSERT_FALSE(FLAGS_SET(svfs.f_flag, ST_RDONLY));

                _exit(EXIT_SUCCESS);
        }
}

TEST(make_mount_point_inode) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        const char *src_file, *src_dir, *dst_file, *dst_dir;
        struct stat st;

        assert_se(mkdtemp_malloc(NULL, &d) >= 0);

        src_file = strjoina(d, "/src/file");
        src_dir = strjoina(d, "/src/dir");
        dst_file = strjoina(d, "/dst/file");
        dst_dir = strjoina(d, "/dst/dir");

        assert_se(mkdir_p(src_dir, 0755) >= 0);
        assert_se(mkdir_parents(dst_file, 0755) >= 0);
        assert_se(touch(src_file) >= 0);

        assert_se(make_mount_point_inode_from_path(src_file, dst_file, 0755) >= 0);
        assert_se(make_mount_point_inode_from_path(src_dir, dst_dir, 0755) >= 0);

        assert_se(stat(dst_dir, &st) == 0);
        assert_se(S_ISDIR(st.st_mode));
        assert_se(stat(dst_file, &st) == 0);
        assert_se(S_ISREG(st.st_mode));
        assert_se(!(S_IXUSR & st.st_mode));
        assert_se(!(S_IXGRP & st.st_mode));
        assert_se(!(S_IXOTH & st.st_mode));

        assert_se(unlink(dst_file) == 0);
        assert_se(rmdir(dst_dir) == 0);

        assert_se(stat(src_file, &st) == 0);
        assert_se(make_mount_point_inode_from_mode(AT_FDCWD, dst_file, st.st_mode, 0755) >= 0);
        assert_se(stat(src_dir, &st) == 0);
        assert_se(make_mount_point_inode_from_mode(AT_FDCWD, dst_dir, st.st_mode, 0755) >= 0);

        assert_se(stat(dst_dir, &st) == 0);
        assert_se(S_ISDIR(st.st_mode));
        assert_se(stat(dst_file, &st) == 0);
        assert_se(S_ISREG(st.st_mode));
        assert_se(!(S_IXUSR & st.st_mode));
        assert_se(!(S_IXGRP & st.st_mode));
        assert_se(!(S_IXOTH & st.st_mode));
}

TEST(make_mount_switch_root) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        CHECK_PRIV;

        assert_se(mkdtemp_malloc(NULL, &t) >= 0);

        assert_se(asprintf(&s, "%s/somerandomname%" PRIu64, t, random_u64()) >= 0);
        assert_se(s);
        assert_se(touch(s) >= 0);

        struct {
                const char *path;
                bool force_ms_move;
        } table[] = {
                { t,   false },
                { t,   true  },
                { "/", false },
                { "/", true  },
        };

        FOREACH_ELEMENT(i, table) {
                r = ASSERT_OK(pidref_safe_fork("(switch-root)", FORK_COMMON_FLAGS, NULL));
                if (r == 0) {
                        assert_se(make_mount_point(i->path) >= 0);
                        assert_se(mount_switch_root_full(i->path, /* mount_propagation_flag= */ 0, i->force_ms_move) >= 0);

                        if (!path_equal(i->path, "/")) {
                                assert_se(access(ASSERT_PTR(strrchr(s, '/')), F_OK) >= 0);       /* absolute */
                                assert_se(access(ASSERT_PTR(strrchr(s, '/')) + 1, F_OK) >= 0);   /* relative */
                                assert_se(access(s, F_OK) < 0 && errno == ENOENT);               /* doesn't exist in our new environment */
                        }

                        _exit(EXIT_SUCCESS);
                }
        }
}

TEST(umount_recursive) {
        static const struct {
                const char *prefix;
                const char * const keep[3];
        } test_table[] = {
                {
                        .prefix = NULL,
                        .keep = {},
                },
                {
                        .prefix = "/run",
                        .keep = {},
                },
                {
                        .prefix = NULL,
                        .keep = { "/dev/shm", NULL },
                },
                {
                        .prefix = "/dev",
                        .keep = { "/dev/pts", "/dev/shm", NULL },
                },
        };

        int r;

        CHECK_PRIV;

        int have_kernel = have_kernel_mount_table();

        /* As above: one pass per backend, decided in the forked child. */
        FOREACH_STRING(backend, "1", "0") {
                SKIP_UNLESS_KERNEL_TABLE(backend, have_kernel);

                FOREACH_ELEMENT(t, test_table) {
                        r = ASSERT_OK(pidref_safe_fork("(umount-rec)", FORK_COMMON_FLAGS, NULL));
                        if (r == 0) { /* child */
                                _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
                                _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
                                _cleanup_fclose_ FILE *f = NULL;
                                _cleanup_free_ char *k = NULL;

                                ASSERT_OK_ERRNO(setenv("SYSTEMD_LISTMOUNT", backend, /* overwrite= */ true));

                                /* Open /p/s/m file before we unmount everything (which might include /proc/) */
                                f = fopen("/proc/self/mountinfo", "re");
                                if (!f) {
                                        log_error_errno(errno, "Failed to open %s: %m", "/proc/self/mountinfo");
                                        _exit(EXIT_FAILURE);
                                }

                                assert_se(k = strv_join((char**) t->keep, " "));
                                log_info("detaching just %s (keep: %s)", strna(t->prefix), strna(empty_to_null(k)));

                                assert_se(umount_recursive_full(t->prefix, MNT_DETACH, (char**) t->keep) >= 0);

                                r = libmount_parse_mountinfo(f, &table, &iter);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");
                                        _exit(EXIT_FAILURE);
                                }

                                for (;;) {
                                        struct libmnt_fs *fs;

                                        r = sym_mnt_table_next_fs(table, iter, &fs);
                                        if (r == 1)
                                                break;
                                        if (r < 0) {
                                                log_error_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");
                                                _exit(EXIT_FAILURE);
                                        }

                                        log_debug("left after complete umount: %s", sym_mnt_fs_get_target(fs));
                                }

                                _exit(EXIT_SUCCESS);
                        }
                }
        }
}

/* The fields the dedup check below reads from each entry: the mount point, the filesystem type,
 * and the VFS option flags. */
#define DEDUP_STATMOUNT_MASK \
        (STATMOUNT_MNT_BASIC|STATMOUNT_MNT_POINT|STATMOUNT_FS_TYPE)

/* "<fstype> <flags>" for one entry, as mount_snapshot_from_table() would record it, or NULL when
 * the entry cannot be read in full. */
static char* mount_dedup_value(struct libmnt_fs *fs) {
        unsigned long fl = 0;
        const char *opts;
        char *v;

        ASSERT_NOT_NULL(fs);

        opts = sym_mnt_fs_get_vfs_options(fs);
        if (!opts) /* The mount vanished between listmount() and statmount() */
                return NULL;

        ASSERT_OK(sym_mnt_optstr_get_flags(opts, &fl, sym_mnt_get_builtin_optmap(MNT_LINUX_MAP)));
        fl &= ~MS_STRICTATIME; /* As mount_fs_flags() does */

        ASSERT_OK(asprintf(&v, "%s %lx", strempty(sym_mnt_fs_get_fstype(fs)), fl));
        return v;
}

TEST(mount_table_kernel_dedup_direction) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        int r;

        /* bind_remount_recursive_with_mountinfo() walks the kernel table forwards and lets the
         * last entry for a path win; the umount path walks backwards and acts on the top of an
         * overmount stack first. Both orders must find the same mount for every overmounted
         * path. One snapshot, walked both ways, so there is no second table to race against.
         * The child stacks two tmpfs mounts on a directory of its own first, so at least one
         * overmounted path exists whatever the host's table looks like, and the winner there is
         * known: the top mount, the one carrying MS_NOSUID. */

        CHECK_PRIV;

        r = have_kernel_mount_table();
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("listmount()/statmount() are not available");
        ASSERT_OK(r);

        ASSERT_OK(mkdtemp_malloc(NULL, &t));

        r = ASSERT_OK(pidref_safe_fork("(dedup-direction)", FORK_COMMON_FLAGS, NULL));
        if (r == 0) { /* child */
                _cleanup_(mnt_free_tablep) struct libmnt_table *kernel_table = NULL;
                _cleanup_(mnt_free_iterp) struct libmnt_iter *kernel_iter = NULL, *forward_iter = NULL;
                _cleanup_hashmap_free_ Hashmap *backward = NULL, *forward = NULL;
                const char *fw_path;
                char *backward_v;

                ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", t, "tmpfs", 0, NULL));
                ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", t, "tmpfs", MS_NOSUID, NULL));

                ASSERT_OK(libmount_parse_kernel(DEDUP_STATMOUNT_MASK, MNT_ITER_BACKWARD,
                                                &kernel_table, &kernel_iter));

                for (;;) {
                        _cleanup_free_ char *p = NULL, *v = NULL;
                        const char *path;
                        struct libmnt_fs *fs;

                        r = sym_mnt_table_next_fs(kernel_table, kernel_iter, &fs);
                        if (r == 1)
                                break;
                        ASSERT_OK_ZERO(r);

                        path = sym_mnt_fs_get_target(fs);
                        if (isempty(path))
                                continue;

                        v = mount_dedup_value(fs);
                        if (!v)
                                continue;

                        ASSERT_NOT_NULL(p = strdup(path));

                        r = hashmap_ensure_put(&backward, &string_hash_ops_free_free, p, v);
                        if (r == -EEXIST) /* An overmounted path; the topmost mount is already stored */
                                continue;
                        ASSERT_OK(r);
                        TAKE_PTR(p);
                        TAKE_PTR(v);
                }

                ASSERT_NOT_NULL(forward_iter = sym_mnt_new_iter(MNT_ITER_FORWARD));
                for (;;) {
                        _cleanup_free_ char *p = NULL, *v = NULL, *old_key = NULL;
                        const char *path;
                        struct libmnt_fs *fs;

                        r = sym_mnt_table_next_fs(kernel_table, forward_iter, &fs);
                        if (r == 1)
                                break;
                        ASSERT_OK_ZERO(r);

                        path = sym_mnt_fs_get_target(fs);
                        if (isempty(path))
                                continue;

                        v = mount_dedup_value(fs);
                        if (!v)
                                continue;

                        /* hashmap_remove2() hands back the removed key and returns the removed
                         * value, which has no owner anymore and is freed right here. */
                        free(hashmap_remove2(forward, path, (void**) &old_key));

                        ASSERT_NOT_NULL(p = strdup(path));
                        ASSERT_OK(hashmap_ensure_put(&forward, &string_hash_ops_free_free, p, v));
                        TAKE_PTR(p);
                        TAKE_PTR(v);
                }

                ASSERT_EQ(hashmap_size(forward), hashmap_size(backward));
                HASHMAP_FOREACH_KEY(backward_v, fw_path, backward) {
                        const char *fw_v = hashmap_get(forward, fw_path);
                        if (!streq_ptr(fw_v, backward_v))
                                log_error("Iteration direction changed the winner at '%s': forward '%s', backward '%s'",
                                          fw_path, strnull(fw_v), backward_v);
                        ASSERT_STREQ(fw_v, backward_v);
                }

                /* The stacked pair above guarantees the dedup branches ran, and pins the winner:
                 * both directions must have kept the top mount. */
                const char *stacked_v = ASSERT_NOT_NULL(hashmap_get(forward, t));
                unsigned long stacked_flags = 0;
                ASSERT_EQ(sscanf(stacked_v, "tmpfs %lx", &stacked_flags), 1);
                ASSERT_TRUE(FLAGS_SET(stacked_flags, MS_NOSUID));

                _exit(EXIT_SUCCESS);
        }
}

TEST(fd_make_mount_point) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        CHECK_PRIV;

        assert_se(mkdtemp_malloc(NULL, &t) >= 0);

        assert_se(asprintf(&s, "%s/somerandomname%" PRIu64, t, random_u64()) >= 0);
        assert_se(s);
        assert_se(mkdir(s, 0700) >= 0);

        r = ASSERT_OK(pidref_safe_fork("(make-mount-point)", FORK_COMMON_FLAGS, NULL));
        if (r == 0) {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;

                fd = open(s, O_PATH|O_CLOEXEC);
                assert_se(fd >= 0);

                assert_se(is_mount_point_at(fd, NULL, AT_SYMLINK_FOLLOW) == 0);

                assert_se(fd_make_mount_point(fd) > 0);

                /* Reopen the inode so that we end up on the new mount */
                fd2 = open(s, O_PATH|O_CLOEXEC);

                assert_se(is_mount_point_at(fd2, NULL, AT_SYMLINK_FOLLOW) > 0);

                assert_se(fd_make_mount_point(fd2) == 0);

                _exit(EXIT_SUCCESS);
        }
}

TEST(bind_mount_submounts) {
        _cleanup_(rmdir_and_freep) char *a = NULL, *b = NULL;
        int r;

        CHECK_PRIV;

        assert_se(mkdtemp_malloc(NULL, &a) >= 0);
        assert_se(mkdtemp_malloc(NULL, &b) >= 0);

        r = ASSERT_OK(pidref_safe_fork("(bind-mount-submounts)", FORK_COMMON_FLAGS, NULL));
        if (r == 0) {
                char *x;

                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", a, "tmpfs", 0, NULL));

                assert_se(x = path_join(a, "foo"));
                assert_se(touch(x) >= 0);
                free(x);

                assert_se(x = path_join(a, "x"));
                assert_se(mkdir(x, 0755) >= 0);
                assert_se(mount_nofollow_verbose(LOG_INFO, "tmpfs", x, "tmpfs", 0, NULL) >= 0);
                free(x);

                assert_se(x = path_join(a, "x/xx"));
                assert_se(touch(x) >= 0);
                free(x);

                assert_se(x = path_join(a, "y"));
                assert_se(mkdir(x, 0755) >= 0);
                assert_se(mount_nofollow_verbose(LOG_INFO, "tmpfs", x, "tmpfs", 0, NULL) >= 0);
                free(x);

                assert_se(x = path_join(a, "y/yy"));
                assert_se(touch(x) >= 0);
                free(x);

                assert_se(mount_nofollow_verbose(LOG_INFO, "tmpfs", b, "tmpfs", 0, NULL) >= 0);

                assert_se(x = path_join(b, "x"));
                assert_se(mkdir(x, 0755) >= 0);
                free(x);

                assert_se(x = path_join(b, "y"));
                assert_se(mkdir(x, 0755) >= 0);
                free(x);

                assert_se(bind_mount_submounts(a, b) >= 0);

                assert_se(x = path_join(b, "foo"));
                assert_se(access(x, F_OK) < 0 && errno == ENOENT);
                free(x);

                assert_se(x = path_join(b, "x/xx"));
                assert_se(access(x, F_OK) >= 0);
                free(x);

                assert_se(x = path_join(b, "y/yy"));
                assert_se(access(x, F_OK) >= 0);
                free(x);

                assert_se(x = path_join(b, "x"));
                assert_se(path_is_mount_point(x) > 0);
                free(x);

                assert_se(x = path_join(b, "y"));
                assert_se(path_is_mount_point(x) > 0);
                free(x);

                assert_se(umount_recursive(a, 0) >= 0);
                assert_se(umount_recursive(b, 0) >= 0);

                _exit(EXIT_SUCCESS);
        }
}

TEST(get_sub_mounts) {
        _cleanup_(rm_rf_physical_and_freep) char *a = NULL;
        int r;

        CHECK_PRIV;

        ASSERT_OK(mkdtemp_malloc(NULL, &a));

        r = ASSERT_OK(pidref_safe_fork("(get-sub-mounts)", FORK_COMMON_FLAGS, NULL));
        if (r == 0) {
                SubMount *mounts = NULL;
                size_t n = 0;

                CLEANUP_ARRAY(mounts, n, sub_mount_array_free);

                /* Reproduces the layout that triggered the assertion crash in systemd-sysext on
                 * Flatcar (https://github.com/flatcar/Flatcar/issues/2111): a mount nested inside
                 * another mount under a sysext hierarchy. The dedup pass must keep only the outer
                 * entry (the inner is covered by the outer's recursive open_tree() clone) and
                 * compact the array — leaving NULL entries behind would crash the consumer. */

                _cleanup_free_ char *outer = ASSERT_NOT_NULL(path_join(a, "outer"));
                ASSERT_OK_ERRNO(mkdir(outer, 0755));
                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", outer, "tmpfs", 0, NULL));

                _cleanup_free_ char *inner = ASSERT_NOT_NULL(path_join(outer, "inner"));
                ASSERT_OK_ERRNO(mkdir(inner, 0755));
                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", inner, "tmpfs", 0, NULL));

                r = get_sub_mounts(a, &mounts, &n);
                if (r == -EOPNOTSUPP) {
                        log_tests_skipped("libmount support not compiled in");
                        _exit(EXIT_SUCCESS);
                }
                ASSERT_OK(r);

                /* Only the outer entry should survive dedup; the inner is implied by the outer's
                 * recursive clone. */
                ASSERT_EQ(n, 1u);
                ASSERT_NOT_NULL(mounts[0].path);
                ASSERT_STREQ(mounts[0].path, outer);
                ASSERT_OK(mounts[0].mount_fd);

                ASSERT_OK(umount_recursive(a, 0));

                _exit(EXIT_SUCCESS);
        }
}

TEST(path_is_network_fs_harder) {
        _cleanup_close_ int dir_fd = -EBADF;
        int r;

        ASSERT_OK(dir_fd = open("/", O_PATH | O_CLOEXEC));
        FOREACH_STRING(s,
                       "/", "/dev/", "/proc/", "/run/", "/sys/", "/tmp/", "/usr/", "/var/tmp/",
                       "", ".", "../../../", "/this/path/should/not/exist/for/test-mount-util/") {

                r = path_is_network_fs_harder(s);
                log_debug("path_is_network_fs_harder(%s) → %i: %s", s, r, r < 0 ? STRERROR(r) : yes_no(r));

                const char *q = path_startswith(s, "/") ?: s;
                r = path_is_network_fs_harder_at(dir_fd, q);
                log_debug("path_is_network_fs_harder_at(root, %s) → %i: %s", q, r, r < 0 ? STRERROR(r) : yes_no(r));
        }

        CHECK_PRIV;

        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        assert_se(mkdtemp_malloc("/tmp/test-mount-util.path_is_network_fs_harder.XXXXXXX", &t) >= 0);

        r = ASSERT_OK(pidref_safe_fork("(path-is-network-fs-harder)", FORK_COMMON_FLAGS, NULL));
        if (r == 0) {
                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", t, "tmpfs", 0, NULL));
                ASSERT_OK_ZERO(path_is_network_fs_harder(t));
                ASSERT_OK_ERRNO(umount(t));

                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", t, "tmpfs", 0, "x-systemd-growfs,x-systemd-automount"));
                ASSERT_OK_ZERO(path_is_network_fs_harder(t));
                ASSERT_OK_ERRNO(umount(t));

                _exit(EXIT_SUCCESS);
        }
}

TEST(umountat) {
        CHECK_PRIV;

        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        _cleanup_close_ int dfd = mkdtemp_open(NULL, O_CLOEXEC, &p);
        ASSERT_OK(dfd);

        ASSERT_OK(mkdirat(dfd, "foo", 0777));

        _cleanup_free_ char *q = ASSERT_PTR(path_join(p, "foo"));

        ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", q, "tmpfs", 0, NULL));
        ASSERT_OK(umountat_detach_verbose(LOG_ERR, dfd, "foo"));
        ASSERT_ERROR(umountat_detach_verbose(LOG_ERR, dfd, "foo"), EINVAL);
}

TEST(mount_fd_clone) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        int r;

        CHECK_PRIV;

        ASSERT_OK(mkdtemp_malloc(NULL, &t));

        /* Set up a socket pair to transfer the mount fd from the child (in a different mountns) to us. */
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, fds));

        r = ASSERT_OK(pidref_safe_fork_full(
                        "(mount-fd-clone-setup)",
                        /* stdio_fds= */ NULL,
                        &fds[1], 1,
                        FORK_COMMON_FLAGS,
                        NULL));
        if (r == 0) {
                /* Create a tmpfs mount in this child's mountns. */
                ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", t, "tmpfs", 0, NULL));

                /* Create a file in it to verify the mount later. */
                _cleanup_free_ char *marker = ASSERT_NOT_NULL(path_join(t, "marker"));
                ASSERT_OK(touch(marker));

                /* Clone the mount as a detached mount fd. */
                _cleanup_close_ int mount_fd = ASSERT_OK_ERRNO(open_tree(AT_FDCWD, t, OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC));

                /* Send the mount fd to the parent. */
                ASSERT_OK(send_one_fd(fds[1], mount_fd, 0));

                _exit(EXIT_SUCCESS);
        }

        fds[1] = safe_close(fds[1]);

        /* Parent: Receive the mount fd, clone it with mount_fd_clone(), and verify we can attach it. */
        _cleanup_close_ int foreign_mount_fd = ASSERT_OK(receive_one_fd(fds[0], 0));
        _cleanup_close_ int first_clone = ASSERT_OK(
                        mount_fd_clone(foreign_mount_fd, /* recursive= */ true, &foreign_mount_fd));
        _cleanup_close_ _unused_ int second_clone = ASSERT_OK(
                        mount_fd_clone(foreign_mount_fd, /* recursive= */ true, /* replacement_fd= */ NULL));
        _cleanup_free_ char *target = ASSERT_NOT_NULL(path_join(t, "target"));
        ASSERT_OK_ERRNO(mkdir(target, 0755));

        r = ASSERT_OK(pidref_safe_fork_full(
                        "(mount-fd-clone-verify)",
                        /* stdio_fds= */ NULL,
                        &first_clone, 1,
                        FORK_COMMON_FLAGS,
                        NULL));
        if (r == 0) {
                ASSERT_OK_ERRNO(move_mount(first_clone, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH));

                _cleanup_free_ char *marker = ASSERT_NOT_NULL(path_join(target, "marker"));
                ASSERT_OK_ERRNO(access(marker, F_OK));

                _exit(EXIT_SUCCESS);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
