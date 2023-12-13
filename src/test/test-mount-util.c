/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/statvfs.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "libmount-util.h"
#include "missing_magic.h"
#include "missing_mount.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(mount_option_mangle) {
        char *opts = NULL;
        unsigned long f;

        assert_se(mount_option_mangle(NULL, MS_RDONLY|MS_NOSUID, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID));
        assert_se(opts == NULL);

        assert_se(mount_option_mangle("", MS_RDONLY|MS_NOSUID, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID));
        assert_se(opts == NULL);

        assert_se(mount_option_mangle("ro,nosuid,nodev,noexec", 0, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        assert_se(opts == NULL);

        assert_se(mount_option_mangle("ro,nosuid,nodev,noexec,mode=0755", 0, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        assert_se(streq(opts, "mode=0755"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,foo,hogehoge,nodev,mode=0755", 0, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV));
        assert_se(streq(opts, "foo,hogehoge,mode=0755"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,nodev,noexec,relatime,net_cls,net_prio", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME));
        assert_se(streq(opts, "net_cls,net_prio"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,nodev,relatime,size=1630748k,mode=0700,uid=1000,gid=1000", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_RELATIME));
        assert_se(streq(opts, "size=1630748k,mode=0700,uid=1000,gid=1000"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("size=1630748k,rw,gid=1000,,,nodev,relatime,,mode=0700,nosuid,uid=1000", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_RELATIME));
        assert_se(streq(opts, "size=1630748k,gid=1000,mode=0700,uid=1000"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,exec,size=8143984k,nr_inodes=2035996,mode=0755", MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV));
        assert_se(streq(opts, "size=8143984k,nr_inodes=2035996,mode=0755"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,relatime,fmask=0022,,,dmask=0022", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == MS_RELATIME);
        assert_se(streq(opts, "fmask=0022,dmask=0022"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,relatime,fmask=0022,dmask=0022,\"hogehoge", MS_RDONLY, &f, &opts) < 0);

        assert_se(mount_option_mangle("mode=01777,size=10%,nr_inodes=400k,uid=496107520,gid=496107520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"", 0, &f, &opts) == 0);
        assert_se(f == 0);
        assert_se(streq(opts, "mode=01777,size=10%,nr_inodes=400k,uid=496107520,gid=496107520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\""));
        opts = mfree(opts);
}

static void test_mount_flags_to_string_one(unsigned long flags, const char *expected) {
        _cleanup_free_ char *x = NULL;
        int r;

        r = mount_flags_to_string(flags, &x);
        log_info("flags: %#lX → %d/\"%s\"", flags, r, strnull(x));
        assert_se(r >= 0);
        assert_se(streq(x, expected));
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

        if (geteuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                (void) log_tests_skipped("not running privileged");
                return;
        }

        assert_se(mkdtemp_malloc("/tmp/XXXXXX", &tmp) >= 0);
        subdir = path_join(tmp, "subdir");
        assert_se(subdir);
        assert_se(mkdir(subdir, 0755) >= 0);

        FOREACH_STRING(p, "/usr", "/sys", "/", tmp) {
                pid_t pid;

                pid = fork();
                assert_se(pid >= 0);

                if (pid == 0) {
                        struct statvfs svfs;
                        /* child */
                        assert_se(detach_mount_namespace() >= 0);

                        /* Check that the subdir is writable (it must be because it's in /tmp) */
                        assert_se(statvfs(subdir, &svfs) >= 0);
                        assert_se(!FLAGS_SET(svfs.f_flag, ST_RDONLY));

                        /* Make the subdir a bind mount */
                        assert_se(mount_nofollow(subdir, subdir, NULL, MS_BIND|MS_REC, NULL) >= 0);

                        /* Ensure it's still writable */
                        assert_se(statvfs(subdir, &svfs) >= 0);
                        assert_se(!FLAGS_SET(svfs.f_flag, ST_RDONLY));

                        /* Now mark the path we currently run for read-only */
                        assert_se(bind_remount_recursive(p, MS_RDONLY, MS_RDONLY, path_equal(p, "/sys") ? STRV_MAKE("/sys/kernel") : NULL) >= 0);

                        /* Ensure that this worked on the top-level */
                        assert_se(statvfs(p, &svfs) >= 0);
                        assert_se(FLAGS_SET(svfs.f_flag, ST_RDONLY));

                        /* And ensure this had an effect on the subdir exactly if we are talking about a path above the subdir */
                        assert_se(statvfs(subdir, &svfs) >= 0);
                        assert_se(FLAGS_SET(svfs.f_flag, ST_RDONLY) == !!path_startswith(subdir, p));

                        _exit(EXIT_SUCCESS);
                }

                assert_se(wait_for_terminate_and_check("test-remount-rec", pid, WAIT_LOG) == EXIT_SUCCESS);
        }
}

TEST(bind_remount_one) {
        pid_t pid;

        if (geteuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                (void) log_tests_skipped("not running privileged");
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                /* child */

                _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

                assert_se(detach_mount_namespace() >= 0);

                assert_se(fopen_unlocked("/proc/self/mountinfo", "re", &proc_self_mountinfo) >= 0);

                assert_se(bind_remount_one_with_mountinfo("/run", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) >= 0);
                assert_se(bind_remount_one_with_mountinfo("/run", MS_NOEXEC, MS_RDONLY|MS_NOEXEC, proc_self_mountinfo) >= 0);
                assert_se(bind_remount_one_with_mountinfo("/proc/idontexist", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) == -ENOENT);
                assert_se(bind_remount_one_with_mountinfo("/proc/self", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) == -EINVAL);
                assert_se(bind_remount_one_with_mountinfo("/", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) >= 0);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("test-remount-one", pid, WAIT_LOG) == EXIT_SUCCESS);
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
        assert_se(make_mount_point_inode_from_stat(&st, dst_file, 0755) >= 0);
        assert_se(stat(src_dir, &st) == 0);
        assert_se(make_mount_point_inode_from_stat(&st, dst_dir, 0755) >= 0);

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

        if (geteuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                (void) log_tests_skipped("not running privileged");
                return;
        }

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

        FOREACH_ARRAY(i, table, ELEMENTSOF(table)) {
                r = safe_fork("(switch-root)",
                              FORK_RESET_SIGNALS |
                              FORK_CLOSE_ALL_FDS |
                              FORK_DEATHSIG_SIGTERM |
                              FORK_WAIT |
                              FORK_REOPEN_LOG |
                              FORK_LOG |
                              FORK_NEW_MOUNTNS |
                              FORK_MOUNTNS_SLAVE,
                              NULL);
                assert_se(r >= 0);

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

        FOREACH_ARRAY(t, test_table, ELEMENTSOF(test_table)) {

                r = safe_fork("(umount-rec)",
                              FORK_RESET_SIGNALS |
                              FORK_CLOSE_ALL_FDS |
                              FORK_DEATHSIG_SIGTERM |
                              FORK_WAIT |
                              FORK_REOPEN_LOG |
                              FORK_LOG |
                              FORK_NEW_MOUNTNS |
                              FORK_MOUNTNS_SLAVE,
                              NULL);

                if (ERRNO_IS_NEG_PRIVILEGE(r))
                        return (void) log_notice("Skipping umount_recursive() test, lacking privileges");

                assert_se(r >= 0);
                if (r == 0) { /* child */
                        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
                        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        _cleanup_free_ char *k = NULL;

                        /* Open /p/s/m file before we unmount everything (which might include /proc/) */
                        f = fopen("/proc/self/mountinfo", "re");
                        if (!f) {
                                log_error_errno(errno, "Failed to open /proc/self/mountinfo: %m");
                                _exit(EXIT_FAILURE);
                        }

                        assert_se(k = strv_join((char**) t->keep, " "));
                        log_info("detaching just %s (keep: %s)", strna(t->prefix), strna(empty_to_null(k)));

                        assert_se(umount_recursive_full(t->prefix, MNT_DETACH, (char**) t->keep) >= 0);

                        r = libmount_parse("/proc/self/mountinfo", f, &table, &iter);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");
                                _exit(EXIT_FAILURE);
                        }

                        for (;;) {
                                struct libmnt_fs *fs;

                                r = mnt_table_next_fs(table, iter, &fs);
                                if (r == 1)
                                        break;
                                if (r < 0) {
                                        log_error_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");
                                        _exit(EXIT_FAILURE);
                                }

                                log_debug("left after complete umount: %s", mnt_fs_get_target(fs));
                        }

                        _exit(EXIT_SUCCESS);
                }
        }
}

TEST(fd_make_mount_point) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        if (geteuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                (void) log_tests_skipped("not running privileged");
                return;
        }

        assert_se(mkdtemp_malloc(NULL, &t) >= 0);

        assert_se(asprintf(&s, "%s/somerandomname%" PRIu64, t, random_u64()) >= 0);
        assert_se(s);
        assert_se(mkdir(s, 0700) >= 0);

        r = safe_fork("(make_mount-point)",
                      FORK_RESET_SIGNALS |
                      FORK_CLOSE_ALL_FDS |
                      FORK_DEATHSIG_SIGTERM |
                      FORK_WAIT |
                      FORK_REOPEN_LOG |
                      FORK_LOG |
                      FORK_NEW_MOUNTNS |
                      FORK_MOUNTNS_SLAVE,
                      NULL);
        assert_se(r >= 0);

        if (r == 0) {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;

                fd = open(s, O_PATH|O_CLOEXEC);
                assert_se(fd >= 0);

                assert_se(fd_is_mount_point(fd, NULL, AT_SYMLINK_FOLLOW) == 0);

                assert_se(fd_make_mount_point(fd) > 0);

                /* Reopen the inode so that we end up on the new mount */
                fd2 = open(s, O_PATH|O_CLOEXEC);

                assert_se(fd_is_mount_point(fd2, NULL, AT_SYMLINK_FOLLOW) > 0);

                assert_se(fd_make_mount_point(fd2) == 0);

                _exit(EXIT_SUCCESS);
        }
}

TEST(bind_mount_submounts) {
        _cleanup_(rmdir_and_freep) char *a = NULL, *b = NULL;
        _cleanup_free_ char *x = NULL;
        int r;

        assert_se(mkdtemp_malloc(NULL, &a) >= 0);
        r = mount_nofollow_verbose(LOG_INFO, "tmpfs", a, "tmpfs", 0, NULL);
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped("Skipping bind_mount_submounts() test, lacking privileges");

        assert_se(r >= 0);

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

        assert_se(mkdtemp_malloc(NULL, &b) >= 0);
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
        assert_se(path_is_mount_point(x, NULL, 0) > 0);
        free(x);

        assert_se(x = path_join(b, "y"));
        assert_se(path_is_mount_point(x, NULL, 0) > 0);

        assert_se(umount_recursive(a, 0) >= 0);
        assert_se(umount_recursive(b, 0) >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
