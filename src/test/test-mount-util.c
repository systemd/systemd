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

TEST(mount_option_mangle) {
        char *opts = NULL;
        unsigned long f;

        ASSERT_OK_ZERO(mount_option_mangle(/* options= */ NULL, MS_RDONLY|MS_NOSUID, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_RDONLY|MS_NOSUID));
        ASSERT_NULL(opts);

        ASSERT_OK_ZERO(mount_option_mangle("", MS_RDONLY|MS_NOSUID, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_RDONLY|MS_NOSUID));
        ASSERT_NULL(opts);

        ASSERT_OK_ZERO(mount_option_mangle("ro,nosuid,nodev,noexec", /* mount_flags= */ 0, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        ASSERT_NULL(opts);

        ASSERT_OK_ZERO(mount_option_mangle("ro,nosuid,nodev,noexec,mode=0755", /* mount_flags= */ 0, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        ASSERT_STREQ(opts, "mode=0755");
        opts = mfree(opts);

        ASSERT_OK_ZERO(mount_option_mangle("rw,nosuid,foo,hogehoge,nodev,mode=0755", /* mount_flags= */ 0, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_NOSUID|MS_NODEV));
        ASSERT_STREQ(opts, "foo,hogehoge,mode=0755");
        opts = mfree(opts);

        ASSERT_OK_ZERO(mount_option_mangle("rw,nosuid,nodev,noexec,relatime,net_cls,net_prio", MS_RDONLY, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME));
        ASSERT_STREQ(opts, "net_cls,net_prio");
        opts = mfree(opts);

        ASSERT_OK_ZERO(mount_option_mangle("rw,nosuid,nodev,relatime,size=1630748k,mode=0700,uid=1000,gid=1000", MS_RDONLY, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_NOSUID|MS_NODEV|MS_RELATIME));
        ASSERT_STREQ(opts, "size=1630748k,mode=0700,uid=1000,gid=1000");
        opts = mfree(opts);

        ASSERT_OK_ZERO(mount_option_mangle("size=1630748k,rw,gid=1000,,,nodev,relatime,,mode=0700,nosuid,uid=1000", MS_RDONLY, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_NOSUID|MS_NODEV|MS_RELATIME));
        ASSERT_STREQ(opts, "size=1630748k,gid=1000,mode=0700,uid=1000");
        opts = mfree(opts);

        ASSERT_OK_ZERO(mount_option_mangle("rw,exec,size=8143984k,nr_inodes=2035996,mode=0755", MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_NOSUID|MS_NODEV));
        ASSERT_STREQ(opts, "size=8143984k,nr_inodes=2035996,mode=0755");
        opts = mfree(opts);

        ASSERT_OK_ZERO(mount_option_mangle("rw,relatime,fmask=0022,,,dmask=0022", MS_RDONLY, &f, &opts));
        ASSERT_EQ(f, (unsigned long) (MS_RELATIME));
        ASSERT_STREQ(opts, "fmask=0022,dmask=0022");
        opts = mfree(opts);

        ASSERT_FAIL(mount_option_mangle("rw,relatime,fmask=0022,dmask=0022,\"hogehoge", MS_RDONLY, &f, &opts));

        ASSERT_OK_ZERO(mount_option_mangle(
                                  "mode=01777,size=10%,nr_inodes=400k,uid=496107520,gid=496107520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"",
                                  /* mount_flags= */ 0,
                                  &f,
                                  &opts));
        ASSERT_EQ(f, 0U);
        ASSERT_STREQ(opts, "mode=01777,size=10%,nr_inodes=400k,uid=496107520,gid=496107520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"");
        opts = mfree(opts);
}

static void test_mount_flags_to_string_one(unsigned long flags, const char *expected) {
        _cleanup_free_ char *x = NULL;
        int r;

        r = mount_flags_to_string(flags, &x);
        log_info("flags: %#lX → %d/\"%s\"", flags, r, strnull(x));
        ASSERT_OK(r);
        ASSERT_STREQ(x, expected);
}

TEST(mount_flags_to_string) {
        test_mount_flags_to_string_one(/* flags= */ 0, "0");
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

        ASSERT_OK(mkdtemp_malloc("/tmp/XXXXXX", &tmp));
        subdir = ASSERT_NOT_NULL(path_join(tmp, "subdir"));
        ASSERT_OK_ERRNO(mkdir(subdir, 0755));

        FOREACH_STRING(p, "/usr", "/sys", "/", tmp) {
                r = ASSERT_OK(pidref_safe_fork("(bind-remount-recursive)", FORK_COMMON_FLAGS, /* ret= */ NULL));
                if (r == 0) { /* child */
                        struct statvfs svfs;

                        /* Check that the subdir is writable (it must be because it's in /tmp) */
                        ASSERT_OK_ERRNO(statvfs(subdir, &svfs));
                        ASSERT_FALSE(FLAGS_SET(svfs.f_flag, ST_RDONLY));

                        /* Make the subdir a bind mount */
                        ASSERT_OK(mount_nofollow(subdir, subdir, /* filesystemtype= */ NULL, MS_BIND|MS_REC, /* data= */ NULL));

                        /* Ensure it's still writable */
                        ASSERT_OK_ERRNO(statvfs(subdir, &svfs));
                        ASSERT_FALSE(FLAGS_SET(svfs.f_flag, ST_RDONLY));

                        /* Now mark the path we currently run for read-only */
                        ASSERT_OK(bind_remount_recursive(p, MS_RDONLY, MS_RDONLY, path_equal(p, "/sys") ? STRV_MAKE("/sys/kernel") : NULL));

                        /* Ensure that this worked on the top-level */
                        ASSERT_OK_ERRNO(statvfs(p, &svfs));
                        ASSERT_TRUE(FLAGS_SET(svfs.f_flag, ST_RDONLY));

                        /* And ensure this had an effect on the subdir exactly if we are talking about a path above the subdir */
                        ASSERT_OK_ERRNO(statvfs(subdir, &svfs));
                        ASSERT_EQ(FLAGS_SET(svfs.f_flag, ST_RDONLY), !!path_startswith(subdir, p));

                        _exit(EXIT_SUCCESS);
                }
        }
}

TEST(bind_remount_one) {
        int r;

        CHECK_PRIV;

        r = ASSERT_OK(pidref_safe_fork("(remount-one-with-mountinfo)", FORK_COMMON_FLAGS, /* ret= */ NULL));
        if (r == 0) { /* child */
                _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

                ASSERT_OK(fopen_unlocked("/proc/self/mountinfo", "re", &proc_self_mountinfo));

                ASSERT_OK(bind_remount_one_with_mountinfo("/run", MS_RDONLY, MS_RDONLY, proc_self_mountinfo));
                ASSERT_OK(bind_remount_one_with_mountinfo("/run", MS_NOEXEC, MS_RDONLY|MS_NOEXEC, proc_self_mountinfo));
                ASSERT_ERROR(bind_remount_one_with_mountinfo("/proc/idontexist", MS_RDONLY, MS_RDONLY, proc_self_mountinfo), ENOENT);
                ASSERT_ERROR(bind_remount_one_with_mountinfo("/proc/self", MS_RDONLY, MS_RDONLY, proc_self_mountinfo), EINVAL);
                ASSERT_OK(bind_remount_one_with_mountinfo("/", MS_RDONLY, MS_RDONLY, proc_self_mountinfo));

                _exit(EXIT_SUCCESS);
        }

        r = ASSERT_OK(pidref_safe_fork("(remount-one)", FORK_COMMON_FLAGS, /* ret= */ NULL));
        if (r == 0) { /* child */
                ASSERT_OK(bind_remount_one("/run", MS_RDONLY, MS_RDONLY));
                ASSERT_OK(bind_remount_one("/run", MS_NOEXEC, MS_RDONLY|MS_NOEXEC));
                ASSERT_ERROR(bind_remount_one("/proc/idontexist", MS_RDONLY, MS_RDONLY), ENOENT);
                ASSERT_ERROR(bind_remount_one("/proc/self", MS_RDONLY, MS_RDONLY), EINVAL);
                ASSERT_OK(bind_remount_one("/", MS_RDONLY, MS_RDONLY));

                _exit(EXIT_SUCCESS);
        }
}

TEST(make_mount_point_inode) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        const char *src_file, *src_dir, *dst_file, *dst_dir;
        struct stat st;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &d));

        src_file = strjoina(d, "/src/file");
        src_dir = strjoina(d, "/src/dir");
        dst_file = strjoina(d, "/dst/file");
        dst_dir = strjoina(d, "/dst/dir");

        ASSERT_OK(mkdir_p(src_dir, 0755));
        ASSERT_OK(mkdir_parents(dst_file, 0755));
        ASSERT_OK(touch(src_file));

        ASSERT_OK(make_mount_point_inode_from_path(src_file, dst_file, 0755));
        ASSERT_OK(make_mount_point_inode_from_path(src_dir, dst_dir, 0755));

        ASSERT_OK_ZERO_ERRNO(stat(dst_dir, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_OK_ZERO_ERRNO(stat(dst_file, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_FALSE(S_IXUSR & st.st_mode);
        ASSERT_FALSE(S_IXGRP & st.st_mode);
        ASSERT_FALSE(S_IXOTH & st.st_mode);

        ASSERT_OK_ZERO_ERRNO(unlink(dst_file));
        ASSERT_OK_ZERO_ERRNO(rmdir(dst_dir));

        ASSERT_OK_ZERO_ERRNO(stat(src_file, &st));
        ASSERT_OK(make_mount_point_inode_from_mode(AT_FDCWD, dst_file, st.st_mode, 0755));
        ASSERT_OK_ZERO_ERRNO(stat(src_dir, &st));
        ASSERT_OK(make_mount_point_inode_from_mode(AT_FDCWD, dst_dir, st.st_mode, 0755));

        ASSERT_OK_ZERO_ERRNO(stat(dst_dir, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_OK_ZERO_ERRNO(stat(dst_file, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_FALSE(S_IXUSR & st.st_mode);
        ASSERT_FALSE(S_IXGRP & st.st_mode);
        ASSERT_FALSE(S_IXOTH & st.st_mode);
}

TEST(make_mount_switch_root) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        CHECK_PRIV;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));

        ASSERT_OK_ERRNO(asprintf(&s, "%s/somerandomname%" PRIu64, t, random_u64()));
        ASSERT_NOT_NULL(s);
        ASSERT_OK(touch(s));

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
                r = ASSERT_OK(pidref_safe_fork("(switch-root)", FORK_COMMON_FLAGS, /* ret= */ NULL));
                if (r == 0) {
                        ASSERT_OK(make_mount_point(i->path));
                        ASSERT_OK(mount_switch_root_full(i->path, /* mount_propagation_flag= */ 0, i->force_ms_move));

                        if (!path_equal(i->path, "/")) {
                                ASSERT_OK_ERRNO(access(ASSERT_PTR(strrchr(s, '/')), F_OK));       /* absolute */
                                ASSERT_OK_ERRNO(access(ASSERT_PTR(strrchr(s, '/')) + 1, F_OK));   /* relative */
                                ASSERT_ERROR_ERRNO(access(s, F_OK), ENOENT);                     /* doesn't exist in our new environment */
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

        FOREACH_ELEMENT(t, test_table) {
                r = ASSERT_OK(pidref_safe_fork("(umount-rec)", FORK_COMMON_FLAGS, /* ret= */ NULL));
                if (r == 0) { /* child */
                        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
                        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        _cleanup_free_ char *k = NULL;

                        /* Open /p/s/m file before we unmount everything (which might include /proc/) */
                        f = fopen("/proc/self/mountinfo", "re");
                        if (!f) {
                                log_error_errno(errno, "Failed to open %s: %m", "/proc/self/mountinfo");
                                _exit(EXIT_FAILURE);
                        }

                        ASSERT_NOT_NULL(k = strv_join((char**) t->keep, " "));
                        log_info("detaching just %s (keep: %s)", strna(t->prefix), strna(empty_to_null(k)));

                        ASSERT_OK(umount_recursive_full(t->prefix, MNT_DETACH, (char**) t->keep));

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

TEST(fd_make_mount_point) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        CHECK_PRIV;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));

        ASSERT_OK_ERRNO(asprintf(&s, "%s/somerandomname%" PRIu64, t, random_u64()));
        ASSERT_NOT_NULL(s);
        ASSERT_OK_ERRNO(mkdir(s, 0700));

        r = ASSERT_OK(pidref_safe_fork("(make-mount-point)", FORK_COMMON_FLAGS, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;

                fd = ASSERT_OK_ERRNO(open(s, O_PATH|O_CLOEXEC));

                ASSERT_OK_EQ(is_mount_point_at(fd, /* path= */ NULL, AT_SYMLINK_FOLLOW), 0);

                ASSERT_OK_POSITIVE(fd_make_mount_point(fd));

                /* Reopen the inode so that we end up on the new mount */
                fd2 = open(s, O_PATH|O_CLOEXEC);

                ASSERT_OK_POSITIVE(is_mount_point_at(fd2, /* path= */ NULL, AT_SYMLINK_FOLLOW));

                ASSERT_OK_EQ(fd_make_mount_point(fd2), 0);

                _exit(EXIT_SUCCESS);
        }
}

TEST(bind_mount_submounts) {
        _cleanup_(rmdir_and_freep) char *a = NULL, *b = NULL;
        int r;

        CHECK_PRIV;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &a));
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &b));

        r = ASSERT_OK(pidref_safe_fork("(bind-mount-submounts)", FORK_COMMON_FLAGS, /* ret= */ NULL));
        if (r == 0) {
                char *x;

                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", a, "tmpfs", /* flags= */ 0, /* options= */ NULL));

                ASSERT_NOT_NULL(x = path_join(a, "foo"));
                ASSERT_OK(touch(x));
                free(x);

                ASSERT_NOT_NULL(x = path_join(a, "x"));
                ASSERT_OK_ERRNO(mkdir(x, 0755));
                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", x, "tmpfs", /* flags= */ 0, /* options= */ NULL));
                free(x);

                ASSERT_NOT_NULL(x = path_join(a, "x/xx"));
                ASSERT_OK(touch(x));
                free(x);

                ASSERT_NOT_NULL(x = path_join(a, "y"));
                ASSERT_OK_ERRNO(mkdir(x, 0755));
                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", x, "tmpfs", /* flags= */ 0, /* options= */ NULL));
                free(x);

                ASSERT_NOT_NULL(x = path_join(a, "y/yy"));
                ASSERT_OK(touch(x));
                free(x);

                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", b, "tmpfs", /* flags= */ 0, /* options= */ NULL));

                ASSERT_NOT_NULL(x = path_join(b, "x"));
                ASSERT_OK_ERRNO(mkdir(x, 0755));
                free(x);

                ASSERT_NOT_NULL(x = path_join(b, "y"));
                ASSERT_OK_ERRNO(mkdir(x, 0755));
                free(x);

                ASSERT_OK(bind_mount_submounts(a, b));

                ASSERT_NOT_NULL(x = path_join(b, "foo"));
                ASSERT_ERROR_ERRNO(access(x, F_OK), ENOENT);
                free(x);

                ASSERT_NOT_NULL(x = path_join(b, "x/xx"));
                ASSERT_OK_ERRNO(access(x, F_OK));
                free(x);

                ASSERT_NOT_NULL(x = path_join(b, "y/yy"));
                ASSERT_OK_ERRNO(access(x, F_OK));
                free(x);

                ASSERT_NOT_NULL(x = path_join(b, "x"));
                ASSERT_OK_POSITIVE(path_is_mount_point(x));
                free(x);

                ASSERT_NOT_NULL(x = path_join(b, "y"));
                ASSERT_OK_POSITIVE(path_is_mount_point(x));
                free(x);

                ASSERT_OK(umount_recursive(a, /* flags= */ 0));
                ASSERT_OK(umount_recursive(b, /* flags= */ 0));

                _exit(EXIT_SUCCESS);
        }
}

TEST(get_sub_mounts) {
        _cleanup_(rm_rf_physical_and_freep) char *a = NULL;
        int r;

        CHECK_PRIV;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &a));

        r = ASSERT_OK(pidref_safe_fork("(get-sub-mounts)", FORK_COMMON_FLAGS, /* ret= */ NULL));
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
                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", outer, "tmpfs", /* flags= */ 0, /* options= */ NULL));

                _cleanup_free_ char *inner = ASSERT_NOT_NULL(path_join(outer, "inner"));
                ASSERT_OK_ERRNO(mkdir(inner, 0755));
                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", inner, "tmpfs", /* flags= */ 0, /* options= */ NULL));

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

                ASSERT_OK(umount_recursive(a, /* flags= */ 0));

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
        ASSERT_OK(mkdtemp_malloc("/tmp/test-mount-util.path_is_network_fs_harder.XXXXXXX", &t));

        r = ASSERT_OK(pidref_safe_fork("(path-is-network-fs-harder)", FORK_COMMON_FLAGS, /* ret= */ NULL));
        if (r == 0) {
                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", t, "tmpfs", /* flags= */ 0, /* options= */ NULL));
                ASSERT_OK_ZERO(path_is_network_fs_harder(t));
                ASSERT_OK_ERRNO(umount(t));

                ASSERT_OK(mount_nofollow_verbose(LOG_INFO, "tmpfs", t, "tmpfs", /* flags= */ 0, "x-systemd-growfs,x-systemd-automount"));
                ASSERT_OK_ZERO(path_is_network_fs_harder(t));
                ASSERT_OK_ERRNO(umount(t));

                _exit(EXIT_SUCCESS);
        }
}

TEST(umountat) {
        CHECK_PRIV;

        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        _cleanup_close_ int dfd = mkdtemp_open(/* template= */ NULL, O_CLOEXEC, &p);
        ASSERT_OK(dfd);

        ASSERT_OK(mkdirat(dfd, "foo", 0777));

        _cleanup_free_ char *q = ASSERT_PTR(path_join(p, "foo"));

        ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", q, "tmpfs", /* flags= */ 0, /* options= */ NULL));
        ASSERT_OK(umountat_detach_verbose(LOG_ERR, dfd, "foo"));
        ASSERT_ERROR(umountat_detach_verbose(LOG_ERR, dfd, "foo"), EINVAL);
}

TEST(mount_fd_clone) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        int r;

        CHECK_PRIV;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));

        /* Set up a socket pair to transfer the mount fd from the child (in a different mountns) to us. */
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, fds));

        r = ASSERT_OK(pidref_safe_fork_full(
                        "(mount-fd-clone-setup)",
                        /* stdio_fds= */ NULL,
                        &fds[1], 1,
                        FORK_COMMON_FLAGS,
                        /* ret= */ NULL));
        if (r == 0) {
                /* Create a tmpfs mount in this child's mountns. */
                ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", t, "tmpfs", /* flags= */ 0, /* options= */ NULL));

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
        _cleanup_close_ int foreign_mount_fd = ASSERT_OK(receive_one_fd(fds[0], /* flags= */ 0));
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
                        /* ret= */ NULL));
        if (r == 0) {
                ASSERT_OK_ERRNO(move_mount(first_clone, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH));

                _cleanup_free_ char *marker = ASSERT_NOT_NULL(path_join(target, "marker"));
                ASSERT_OK_ERRNO(access(marker, F_OK));

                _exit(EXIT_SUCCESS);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
