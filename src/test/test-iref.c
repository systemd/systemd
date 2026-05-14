/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fd-util.h"
#include "fileio.h"
#include "iref.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(iref_open_parent) {
        _cleanup_(iref_unrefp) InodeRef *parent = NULL;
        _cleanup_free_ char *fname = NULL;

        if (iref_open_parent(NULL, "/etc/os-release", 0, &parent, &fname) < 0)
                return (void) log_tests_skipped("/etc/os-release not accessible");

        ASSERT_GE(iref_fd(parent), 0);
        ASSERT_STREQ(fname, "os-release");

        /* ret_filename may be NULL — just discard the name. */
        _cleanup_(iref_unrefp) InodeRef *parent2 = NULL;
        ASSERT_OK(iref_open_parent(NULL, "/etc/os-release", 0, &parent2, NULL));
        ASSERT_GE(iref_fd(parent2), 0);
}

TEST(iref_open_parent_relative) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *root = NULL, *parent = NULL;
        _cleanup_free_ char *fname = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &root));

        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open_parent(root, "sub/file", 0, &parent, &fname));
        ASSERT_STREQ(fname, "file");

        /* The returned parent must be the "sub" directory. */
        struct stat a, b;
        _cleanup_(iref_unrefp) InodeRef *sub = NULL;
        ASSERT_OK(iref_open(root, "sub", O_PATH|O_CLOEXEC, MODE_INVALID, &sub));
        ASSERT_OK(iref_stat(parent, &a));
        ASSERT_OK(iref_stat(sub, &b));
        ASSERT_EQ(a.st_ino, b.st_ino);
}

TEST(iref_refcount) {
        _cleanup_(iref_unrefp) InodeRef *i = NULL;

        ASSERT_OK(iref_open(NULL, "/tmp", O_PATH|O_CLOEXEC, MODE_INVALID, &i));

        InodeRef *ref = iref_ref(i);
        ASSERT_PTR_EQ(ref, i);

        ref = iref_unref(ref);
        ASSERT_NULL(ref);
}

TEST(iref_is_set) {
        ASSERT_FALSE(iref_is_set(NULL));

        _cleanup_(iref_unrefp) InodeRef *i = NULL;
        ASSERT_OK(iref_open(NULL, "/tmp", O_PATH|O_CLOEXEC, MODE_INVALID, &i));
        ASSERT_TRUE(iref_is_set(i));
}

TEST(iref_is_root) {
        _cleanup_(iref_unrefp) InodeRef *slash = NULL, *tmp = NULL;

        ASSERT_OK(iref_open(NULL, "/", O_PATH|O_CLOEXEC, MODE_INVALID, &slash));
        ASSERT_GT(iref_is_root(slash), 0);

        ASSERT_OK(iref_open(NULL, "/tmp", O_PATH|O_CLOEXEC, MODE_INVALID, &tmp));
        ASSERT_EQ(iref_is_root(tmp), 0);
}

TEST(iref_path_accessor) {
        _cleanup_(iref_unrefp) InodeRef *i = NULL;

        if (iref_open(NULL, "/etc/os-release", O_PATH|O_CLOEXEC, MODE_INVALID, &i) < 0)
                return (void) log_tests_skipped("/etc/os-release not accessible");
        ASSERT_NOT_NULL(iref_path(i));

        /* Without a custom root, the root path is the host root. */
        ASSERT_STREQ(iref_root_path(i), "/");
}

TEST(iref_make_root_and_paths) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *root = NULL, *child = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &root));

        iref_make_root(root);

        /* For the root iref, iref_path() is "/" while iref_root_path() returns the host path. */
        ASSERT_STREQ(iref_path(root), "/");
        ASSERT_STREQ(iref_root_path(root), tmpdir);

        /* Children inherit the root: their iref_root_path() reports the host path of the boundary. */
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "sub", O_PATH|O_CLOEXEC, MODE_INVALID, &child));
        ASSERT_STREQ(iref_root_path(child), tmpdir);
}

TEST(iref_mkdir_and_unlink_roundtrip) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *parent = NULL, *sub = NULL;
        struct stat st;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));

        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &parent));

        ASSERT_OK(iref_mkdir(parent, "sub", 0755));
        ASSERT_OK(iref_open(parent, "sub", O_PATH|O_CLOEXEC, MODE_INVALID, &sub));

        ASSERT_OK(iref_stat(sub, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));

        ASSERT_OK(iref_unlink(parent, "sub", AT_REMOVEDIR));

        /* The directory entry is gone — re-resolving the name must fail. */
        _cleanup_(iref_unrefp) InodeRef *gone = NULL;
        ASSERT_ERROR(iref_open(parent, "sub", O_PATH|O_CLOEXEC, MODE_INVALID, &gone), ENOENT);
}

TEST(iref_child_inherits_root) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *parent = NULL, *a = NULL, *b = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &parent));

        ASSERT_OK(iref_mkdir(parent, "a", 0755));
        ASSERT_OK(iref_open(parent, "a", O_PATH|O_CLOEXEC, MODE_INVALID, &a));

        ASSERT_OK(iref_mkdir(a, "b", 0755));
        ASSERT_OK(iref_open(a, "b", O_PATH|O_CLOEXEC, MODE_INVALID, &b));
}

TEST(iref_rename_same_root) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *root = NULL;
        struct stat st;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &root));

        /* Create a file "a" and rename it to "b". */
        _cleanup_close_ int fd = openat(iref_fd(root), "a", O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
        ASSERT_OK(fd);
        safe_close(TAKE_FD(fd));

        ASSERT_OK(iref_rename(root, "a", root, "b", 0));

        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "a", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "b", &st, 0));
}

TEST(iref_rename_cross_root) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir_a = NULL, *tmpdir_b = NULL;
        _cleanup_(iref_unrefp) InodeRef *root_a = NULL, *root_b = NULL;
        struct stat st;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir_a));
        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir_b));

        ASSERT_OK(iref_open(NULL, tmpdir_a, O_PATH|O_CLOEXEC, MODE_INVALID, &root_a));
        ASSERT_OK(iref_open(NULL, tmpdir_b, O_PATH|O_CLOEXEC, MODE_INVALID, &root_b));
        iref_make_root(root_a);
        iref_make_root(root_b);

        _cleanup_close_ int fd = openat(iref_fd(root_a), "x", O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
        ASSERT_OK(fd);
        safe_close(TAKE_FD(fd));

        /* Renaming across distinct root boundaries is allowed. */
        ASSERT_OK(iref_rename(root_a, "x", root_b, "y", 0));

        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root_a), "x", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(root_b), "y", &st, 0));
}

TEST(iref_open_for_read) {
        _cleanup_(iref_unrefp) InodeRef *f = NULL;

        if (iref_open(NULL, "/etc/os-release", O_RDONLY|O_CLOEXEC, MODE_INVALID, &f) < 0)
                return (void) log_tests_skipped("/etc/os-release not accessible");

        char buf[1];
        ASSERT_TRUE(read(iref_fd(f), buf, 1) == 1);
}

TEST(iref_fopen_and_access) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *root = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &root));

        ASSERT_OK(write_string_file_at(iref_fd(root), "note", "hello\n",
                                       WRITE_STRING_FILE_CREATE));

        ASSERT_OK(iref_access(root, "note", F_OK));
        ASSERT_ERROR(iref_access(root, "missing", F_OK), ENOENT);

        _cleanup_fclose_ FILE *fp = NULL;
        ASSERT_OK(iref_fopen(root, "note", "re", &fp));

        char buf[16] = {};
        ASSERT_TRUE(fread(buf, 1, sizeof(buf) - 1, fp) == 6);
        ASSERT_STREQ(buf, "hello\n");
}

TEST(iref_readlink_and_symlink_chase) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *root = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &root));

        /* Create "target" regular file and "link" symlink pointing to it. */
        _cleanup_close_ int target_fd = openat(iref_fd(root), "target", O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
        ASSERT_OK(target_fd);
        safe_close(TAKE_FD(target_fd));

        ASSERT_OK_ERRNO(symlinkat("target", iref_fd(root), "link"));

        /* Pin the symlink itself (CHASE_NOFOLLOW stops chase at the symlink, O_NOFOLLOW keeps the
         * final openat from resolving it) and verify iref_readlink reads its target. */
        _cleanup_(iref_unrefp) InodeRef *link = NULL;
        ASSERT_OK(iref_open_full(root, "link", O_PATH|O_NOFOLLOW|O_CLOEXEC, 0, CHASE_NOFOLLOW, MODE_INVALID, &link));

        _cleanup_free_ char *t = NULL;
        ASSERT_OK(iref_readlink(link, &t));
        ASSERT_STREQ(t, "target");

        /* Chasing from a symlink iref resolves through the link target (via i->parent). */
        _cleanup_(iref_unrefp) InodeRef *parent = NULL;
        _cleanup_free_ char *fname = NULL;
        ASSERT_OK(iref_open_parent(link, "", 0, &parent, &fname));
        ASSERT_STREQ(fname, "target");
}

TEST(iref_parent_of_directory) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *root = NULL, *sub = NULL, *parent = NULL;
        struct stat a, b;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &root));

        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "sub", O_PATH|O_CLOEXEC, MODE_INVALID, &sub));

        /* Parent of "sub" must resolve to the same inode as root. */
        ASSERT_OK(iref_parent(sub, &parent));
        ASSERT_OK(iref_stat(parent, &a));
        ASSERT_OK(iref_stat(root, &b));
        ASSERT_EQ(a.st_ino, b.st_ino);

        /* A second call returns an independent InodeRef referring to the same inode. */
        _cleanup_(iref_unrefp) InodeRef *parent2 = NULL;
        ASSERT_OK(iref_parent(sub, &parent2));
        struct stat c;
        ASSERT_OK(iref_stat(parent2, &c));
        ASSERT_EQ(c.st_ino, b.st_ino);
}

TEST(iref_parent_of_file) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *root = NULL, *file = NULL, *parent = NULL;
        struct stat a, b;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &root));

        _cleanup_close_ int fd = openat(iref_fd(root), "f", O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
        ASSERT_OK(fd);
        safe_close(TAKE_FD(fd));

        ASSERT_OK(iref_open(root, "f", O_PATH|O_CLOEXEC, MODE_INVALID, &file));
        ASSERT_OK(iref_parent(file, &parent));

        ASSERT_OK(iref_stat(parent, &a));
        ASSERT_OK(iref_stat(root, &b));
        ASSERT_EQ(a.st_ino, b.st_ino);
}

TEST(iref_parent_of_root_fails) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *root = NULL, *parent = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &root));
        iref_make_root(root);

        ASSERT_ERROR(iref_parent(root, &parent), EINVAL);
}

TEST(iref_rename_self) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) InodeRef *root = NULL, *file = NULL, *dir = NULL;
        struct stat st;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inode.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, O_PATH|O_CLOEXEC, MODE_INVALID, &root));

        /* Self-rename a regular file via its pinned parent. */
        _cleanup_close_ int fd = openat(iref_fd(root), "a", O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
        ASSERT_OK(fd);
        safe_close(TAKE_FD(fd));

        ASSERT_OK(iref_open(root, "a", O_PATH|O_CLOEXEC, MODE_INVALID, &file));
        ASSERT_OK(iref_rename(file, NULL, root, "b", 0));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "a", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "b", &st, 0));

        /* Self-rename a directory — parent is resolved on demand via iref_parent(). */
        ASSERT_OK(iref_mkdir(root, "d", 0755));
        ASSERT_OK(iref_open(root, "d", O_PATH|O_CLOEXEC, MODE_INVALID, &dir));
        ASSERT_OK(iref_rename(dir, NULL, root, "e", 0));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "d", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "e", &st, 0));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
