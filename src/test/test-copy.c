/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "xattr-util.h"

TEST(copy_file) {
        _cleanup_free_ char *buf = NULL;
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-copy_file.XXXXXX";
        _cleanup_(unlink_tempfilep) char fn_copy[] = "/tmp/test-copy_file.XXXXXX";
        size_t sz = 0;
        int fd;

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);
        close(fd);

        fd = mkostemp_safe(fn_copy);
        assert_se(fd >= 0);
        close(fd);

        assert_se(write_string_file(fn, "foo bar bar bar foo", WRITE_STRING_FILE_CREATE) == 0);

        assert_se(copy_file(fn, fn_copy, 0, 0644, COPY_REFLINK) == 0);

        assert_se(read_full_file(fn_copy, &buf, &sz) == 0);
        ASSERT_STREQ(buf, "foo bar bar bar foo\n");
        assert_se(sz == 20);
}

static bool read_file_at_and_streq(int dir_fd, const char *path, const char *expected) {
        _cleanup_free_ char *buf = NULL;

        assert_se(read_full_file_at(dir_fd, path, &buf, NULL) == 0);
        return streq(buf, expected);
}

TEST(copy_tree_replace_file) {
        _cleanup_free_ char *src = NULL, *dst = NULL;

        assert_se(tempfn_random("/tmp/test-copy_file.XXXXXX", NULL, &src) >= 0);
        assert_se(tempfn_random("/tmp/test-copy_file.XXXXXX", NULL, &dst) >= 0);

        assert_se(write_string_file(src, "bar bar", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(dst, "foo foo foo", WRITE_STRING_FILE_CREATE) == 0);

        /* The file exists- now overwrite original contents, and test the COPY_REPLACE flag. */

        assert_se(copy_tree(src, dst, UID_INVALID, GID_INVALID, COPY_REFLINK, NULL, NULL) == -EEXIST);

        assert_se(read_file_at_and_streq(AT_FDCWD, dst, "foo foo foo\n"));

        assert_se(copy_tree(src, dst, UID_INVALID, GID_INVALID, COPY_REFLINK|COPY_REPLACE, NULL, NULL) == 0);

        assert_se(read_file_at_and_streq(AT_FDCWD, dst, "bar bar\n"));
}

TEST(copy_tree_replace_dirs) {
        _cleanup_(rm_rf_physical_and_freep) char *srcp = NULL, *dstp = NULL;
        _cleanup_close_ int src = -EBADF, dst = -EBADF;

        /* Create the random source/destination directories */
        assert_se((src = mkdtemp_open(NULL, 0, &srcp)) >= 0);
        assert_se((dst = mkdtemp_open(NULL, 0, &dstp)) >= 0);

        /* Populate some data to differentiate the files. */
        assert_se(write_string_file_at(src, "foo", "src file 1", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(src, "bar", "src file 2", WRITE_STRING_FILE_CREATE) == 0);

        assert_se(write_string_file_at(dst, "foo", "dest file 1", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file_at(dst, "bar", "dest file 2", WRITE_STRING_FILE_CREATE) == 0);

        /* Copying without COPY_REPLACE should fail because the destination file already exists. */
        assert_se(copy_tree_at(src, ".", dst, ".", UID_INVALID, GID_INVALID, COPY_REFLINK, NULL, NULL) == -EEXIST);

        assert_se(read_file_at_and_streq(src, "foo", "src file 1\n"));
        assert_se(read_file_at_and_streq(src, "bar", "src file 2\n"));
        assert_se(read_file_at_and_streq(dst, "foo", "dest file 1\n"));
        assert_se(read_file_at_and_streq(dst, "bar", "dest file 2\n"));

        assert_se(copy_tree_at(src, ".", dst, ".", UID_INVALID, GID_INVALID, COPY_REFLINK|COPY_REPLACE|COPY_MERGE, NULL, NULL) == 0);

        assert_se(read_file_at_and_streq(src, "foo", "src file 1\n"));
        assert_se(read_file_at_and_streq(src, "bar", "src file 2\n"));
        assert_se(read_file_at_and_streq(dst, "foo", "src file 1\n"));
        assert_se(read_file_at_and_streq(dst, "bar", "src file 2\n"));
}

TEST(copy_file_fd) {
        _cleanup_(unlink_tempfilep) char in_fn[] = "/tmp/test-copy-file-fd-XXXXXX";
        _cleanup_(unlink_tempfilep) char out_fn[] = "/tmp/test-copy-file-fd-XXXXXX";
        _cleanup_close_ int in_fd = -EBADF, out_fd = -EBADF;
        const char *text = "boohoo\nfoo\n\tbar\n";
        char buf[64] = {};

        in_fd = mkostemp_safe(in_fn);
        assert_se(in_fd >= 0);
        out_fd = mkostemp_safe(out_fn);
        assert_se(out_fd >= 0);

        assert_se(write_string_file(in_fn, text, WRITE_STRING_FILE_CREATE) == 0);
        assert_se(copy_file_fd("/a/file/which/does/not/exist/i/guess", out_fd, COPY_REFLINK) < 0);
        assert_se(copy_file_fd(in_fn, out_fd, COPY_REFLINK) >= 0);
        assert_se(lseek(out_fd, SEEK_SET, 0) == 0);

        assert_se(read(out_fd, buf, sizeof buf) == (ssize_t) strlen(text));
        ASSERT_STREQ(buf, text);
}

TEST(copy_tree) {
        _cleanup_hashmap_free_ Hashmap *denylist = NULL;
        _cleanup_free_ char *cp = NULL;
        char original_dir[] = "/tmp/test-copy_tree/";
        char copy_dir[] = "/tmp/test-copy_tree-copy/";
        char **files = STRV_MAKE("file", "dir1/file", "dir1/dir2/file", "dir1/dir2/dir3/dir4/dir5/file");
        char **symlinks = STRV_MAKE("link", "file",
                                    "link2", "dir1/file");
        char **hardlinks = STRV_MAKE("hlink", "file",
                                     "hlink2", "dir1/file");
        const char *unixsockp, *ignorep;
        struct stat st;
        int xattr_worked = -1; /* xattr support is optional in temporary directories, hence use it if we can,
                                * but don't fail if we can't */

        (void) rm_rf(copy_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf(original_dir, REMOVE_ROOT|REMOVE_PHYSICAL);

        STRV_FOREACH(p, files) {
                _cleanup_free_ char *f = NULL, *c = NULL;
                int k;

                assert_se(f = path_join(original_dir, *p));

                assert_se(write_string_file(f, "file", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) == 0);

                assert_se(base64mem(*p, strlen(*p), &c) >= 0);

                k = setxattr(f, "user.testxattr", c, strlen(c), 0);
                assert_se(xattr_worked < 0 || ((k >= 0) == !!xattr_worked));
                xattr_worked = k >= 0;
        }

        STRV_FOREACH_PAIR(ll, p, symlinks) {
                _cleanup_free_ char *f = NULL, *l = NULL;

                assert_se(f = path_join(original_dir, *p));
                assert_se(l = path_join(original_dir, *ll));

                assert_se(mkdir_parents(l, 0755) >= 0);
                assert_se(symlink(f, l) == 0);
        }

        STRV_FOREACH_PAIR(ll, p, hardlinks) {
                _cleanup_free_ char *f = NULL, *l = NULL;

                assert_se(f = path_join(original_dir, *p));
                assert_se(l = path_join(original_dir, *ll));

                assert_se(mkdir_parents(l, 0755) >= 0);
                assert_se(link(f, l) == 0);
        }

        unixsockp = strjoina(original_dir, "unixsock");
        assert_se(mknod(unixsockp, S_IFSOCK|0644, 0) >= 0);

        ignorep = strjoina(original_dir, "ignore/file");
        assert_se(write_string_file(ignorep, "ignore", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) == 0);
        assert_se(RET_NERRNO(stat(ignorep, &st)) >= 0);
        assert_se(cp = memdup(&st, sizeof(st)));
        assert_se(hashmap_ensure_put(&denylist, &inode_hash_ops, cp, INT_TO_PTR(DENY_INODE)) >= 0);
        TAKE_PTR(cp);

        assert_se(copy_tree(original_dir, copy_dir, UID_INVALID, GID_INVALID, COPY_REFLINK|COPY_MERGE|COPY_HARDLINKS, denylist, NULL) == 0);

        STRV_FOREACH(p, files) {
                _cleanup_free_ char *buf = NULL, *f = NULL, *c = NULL;
                size_t sz;
                int k;

                assert_se(f = path_join(copy_dir, *p));

                assert_se(access(f, F_OK) == 0);
                assert_se(read_full_file(f, &buf, &sz) == 0);
                ASSERT_STREQ(buf, "file\n");

                k = lgetxattr_malloc(f, "user.testxattr", &c);
                assert_se(xattr_worked < 0 || ((k >= 0) == !!xattr_worked));

                if (k >= 0) {
                        _cleanup_free_ char *d = NULL;

                        assert_se(base64mem(*p, strlen(*p), &d) >= 0);
                        ASSERT_STREQ(d, c);
                }
        }

        STRV_FOREACH_PAIR(ll, p, symlinks) {
                _cleanup_free_ char *target = NULL, *f = NULL, *l = NULL;

                assert_se(f = strjoin(original_dir, *p));
                assert_se(l = strjoin(copy_dir, *ll));

                assert_se(chase(l, NULL, 0, &target, NULL) == 1);
                assert_se(path_equal(f, target));
        }

        STRV_FOREACH_PAIR(ll, p, hardlinks) {
                _cleanup_free_ char *f = NULL, *l = NULL;
                struct stat a, b;

                assert_se(f = strjoin(copy_dir, *p));
                assert_se(l = strjoin(copy_dir, *ll));

                assert_se(lstat(f, &a) >= 0);
                assert_se(lstat(l, &b) >= 0);

                assert_se(a.st_ino == b.st_ino);
                assert_se(a.st_dev == b.st_dev);
        }

        unixsockp = strjoina(copy_dir, "unixsock");
        assert_se(stat(unixsockp, &st) >= 0);
        assert_se(S_ISSOCK(st.st_mode));

        assert_se(copy_tree(original_dir, copy_dir, UID_INVALID, GID_INVALID, COPY_REFLINK, denylist, NULL) < 0);
        assert_se(copy_tree("/tmp/inexistent/foo/bar/fsdoi", copy_dir, UID_INVALID, GID_INVALID, COPY_REFLINK, denylist, NULL) < 0);

        ignorep = strjoina(copy_dir, "ignore/file");
        assert_se(RET_NERRNO(access(ignorep, F_OK)) == -ENOENT);

        (void) rm_rf(copy_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf(original_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
}

TEST(copy_tree_at_symlink) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *p = NULL, *q = NULL;
        const char *expect = "hgoehogefoobar";

        tfd = mkdtemp_open(NULL, O_PATH, &t);
        assert_se(tfd >= 0);

        assert_se(symlinkat(expect, tfd, "from") >= 0);

        assert_se(copy_tree_at(tfd, "from", tfd, "to_1", UID_INVALID, GID_INVALID, 0, NULL, NULL) >= 0);
        assert_se(readlinkat_malloc(tfd, "to_1", &p) >= 0);
        ASSERT_STREQ(p, expect);
        p = mfree(p);

        assert_se(q = path_join(t, "from"));
        assert_se(copy_tree_at(AT_FDCWD, q, tfd, "to_2", UID_INVALID, GID_INVALID, 0, NULL, NULL) >= 0);
        assert_se(readlinkat_malloc(tfd, "to_2", &p) >= 0);
        ASSERT_STREQ(p, expect);
        p = mfree(p);
        q = mfree(q);

        fd = openat(tfd, "from", O_CLOEXEC | O_PATH | O_NOFOLLOW);
        assert_se(fd >= 0);
        assert_se(copy_tree_at(fd, NULL, tfd, "to_3", UID_INVALID, GID_INVALID, 0, NULL, NULL) >= 0);
        assert_se(readlinkat_malloc(tfd, "to_3", &p) >= 0);
        ASSERT_STREQ(p, expect);
        p = mfree(p);

        assert_se(copy_tree_at(fd, "", tfd, "to_4", UID_INVALID, GID_INVALID, 0, NULL, NULL) >= 0);
        assert_se(readlinkat_malloc(tfd, "to_4", &p) >= 0);
        ASSERT_STREQ(p, expect);
        p = mfree(p);
        fd = safe_close(fd);
}

TEST_RET(copy_bytes) {
        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        _cleanup_close_ int infd = -EBADF;
        int r;
        char buf[1024], buf2[1024];

        infd = open("/usr/lib/os-release", O_RDONLY|O_CLOEXEC);
        if (infd < 0)
                infd = open("/etc/os-release", O_RDONLY|O_CLOEXEC);
        if (infd < 0)
                return log_tests_skipped_errno(errno, "Could not open /usr/lib/os-release or /etc/os-release: %m");

        assert_se(pipe2(pipefd, O_CLOEXEC) == 0);

        r = copy_bytes(infd, pipefd[1], UINT64_MAX, 0);
        assert_se(r == 0);

        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        assert_se(n >= 0);

        assert_se(lseek(infd, 0, SEEK_SET) == 0);
        ssize_t n2 = read(infd, buf2, sizeof(buf2));
        assert_se(n == n2);

        assert_se(strneq(buf, buf2, n));

        /* test copy_bytes with invalid descriptors */
        r = copy_bytes(pipefd[0], pipefd[0], 1, 0);
        assert_se(r == -EBADF);

        r = copy_bytes(pipefd[1], pipefd[1], 1, 0);
        assert_se(r == -EBADF);

        r = copy_bytes(pipefd[1], infd, 1, 0);
        assert_se(r == -EBADF);

        return 0;
}

static void test_copy_bytes_regular_file_one(const char *src, bool try_reflink, uint64_t max_bytes) {
        _cleanup_(unlink_tempfilep) char fn2[] = "/tmp/test-copy-file-XXXXXX";
        _cleanup_(unlink_tempfilep) char fn3[] = "/tmp/test-copy-file-XXXXXX";
        _cleanup_close_ int fd = -EBADF, fd2 = -EBADF, fd3 = -EBADF;
        int r;
        struct stat buf, buf2, buf3;

        log_info("%s try_reflink=%s max_bytes=%" PRIu64, __func__, yes_no(try_reflink), max_bytes);

        fd = open(src, O_CLOEXEC | O_PATH);
        assert_se(fd >= 0);

        fd2 = mkostemp_safe(fn2);
        assert_se(fd2 >= 0);

        fd3 = mkostemp_safe(fn3);
        assert_se(fd3 >= 0);

        r = copy_bytes(fd, fd2, max_bytes, try_reflink ? COPY_REFLINK : 0);
        if (max_bytes == UINT64_MAX)
                assert_se(r == 0);
        else
                assert_se(IN_SET(r, 0, 1));

        assert_se(fstat(fd, &buf) == 0);
        assert_se(fstat(fd2, &buf2) == 0);
        assert_se((uint64_t) buf2.st_size == MIN((uint64_t) buf.st_size, max_bytes));

        if (max_bytes < UINT64_MAX)
                /* Make sure the file is now higher than max_bytes */
                assert_se(ftruncate(fd2, max_bytes + 1) == 0);

        assert_se(lseek(fd2, 0, SEEK_SET) == 0);

        r = copy_bytes(fd2, fd3, max_bytes, try_reflink ? COPY_REFLINK : 0);
        if (max_bytes == UINT64_MAX)
                assert_se(r == 0);
        else
                /* We cannot distinguish between the input being exactly max_bytes
                 * or longer than max_bytes (without trying to read one more byte,
                 * or calling stat, or FION_READ, etc, and we don't want to do any
                 * of that). So we expect "truncation" since we know that file we
                 * are copying is exactly max_bytes bytes. */
                assert_se(r == 1);

        assert_se(fstat(fd3, &buf3) == 0);

        if (max_bytes == UINT64_MAX)
                assert_se(buf3.st_size == buf2.st_size);
        else
                assert_se((uint64_t) buf3.st_size == max_bytes);
}

TEST(copy_bytes_regular_file) {
        test_copy_bytes_regular_file_one(saved_argv[0], false, UINT64_MAX);
        test_copy_bytes_regular_file_one(saved_argv[0], true, UINT64_MAX);
        test_copy_bytes_regular_file_one(saved_argv[0], false, 1000); /* smaller than copy buffer size */
        test_copy_bytes_regular_file_one(saved_argv[0], true, 1000);
        test_copy_bytes_regular_file_one(saved_argv[0], false, 32000); /* larger than copy buffer size */
        test_copy_bytes_regular_file_one(saved_argv[0], true, 32000);
}

TEST(copy_atomic) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        const char *q;
        int r;

        assert_se(mkdtemp_malloc(NULL, &p) >= 0);

        q = strjoina(p, "/fstab");

        r = copy_file_atomic("/etc/fstab", q, 0644, COPY_REFLINK);
        if (r == -ENOENT || ERRNO_IS_PRIVILEGE(r))
                return;

        assert_se(copy_file_atomic("/etc/fstab", q, 0644, COPY_REFLINK) == -EEXIST);

        assert_se(copy_file_atomic("/etc/fstab", q, 0644, COPY_REPLACE) >= 0);
}

TEST(copy_proc) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        _cleanup_free_ char *f = NULL, *a = NULL, *b = NULL;

        /* Check if copying data from /proc/ works correctly, i.e. let's see if https://lwn.net/Articles/846403/ is a problem for us */

        assert_se(mkdtemp_malloc(NULL, &p) >= 0);
        assert_se(f = path_join(p, "version"));
        assert_se(copy_file("/proc/version", f, 0, MODE_INVALID, 0) >= 0);

        assert_se(read_one_line_file("/proc/version", &a) >= 0);
        assert_se(read_one_line_file(f, &b) >= 0);
        ASSERT_STREQ(a, b);
        assert_se(!isempty(a));
}

TEST_RET(copy_holes) {
        _cleanup_(unlink_tempfilep) char fn[] = "/var/tmp/test-copy-hole-fd-XXXXXX";
        _cleanup_(unlink_tempfilep) char fn_copy[] = "/var/tmp/test-copy-hole-fd-XXXXXX";
        struct stat stat;
        off_t blksz;
        int r, fd, fd_copy;
        char *buf;

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        fd_copy = mkostemp_safe(fn_copy);
        assert_se(fd_copy >= 0);

        r = RET_NERRNO(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 1));
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return log_tests_skipped("Filesystem doesn't support hole punching");
        assert_se(r >= 0);

        ASSERT_OK_ERRNO(fstat(fd, &stat));
        blksz = stat.st_blksize;
        buf = alloca_safe(blksz);
        memset(buf, 1, blksz);

        /* We need to make sure to create hole in multiples of the block size, otherwise filesystems (btrfs)
         * might silently truncate/extend the holes. */

        assert_se(lseek(fd, blksz, SEEK_CUR) >= 0);
        assert_se(write(fd, buf, blksz) >= 0);
        assert_se(lseek(fd, 0, SEEK_END) == 2 * blksz);
        /* Only ftruncate() can create holes at the end of a file. */
        assert_se(ftruncate(fd, 3 * blksz) >= 0);
        assert_se(lseek(fd, 0, SEEK_SET) >= 0);

        assert_se(copy_bytes(fd, fd_copy, UINT64_MAX, COPY_HOLES) >= 0);

        /* Test that the hole starts at the beginning of the file. */
        assert_se(lseek(fd_copy, 0, SEEK_HOLE) == 0);
        /* Test that the hole has the expected size. */
        assert_se(lseek(fd_copy, 0, SEEK_DATA) == blksz);
        assert_se(lseek(fd_copy, blksz, SEEK_HOLE) == 2 * blksz);
        assert_se(lseek(fd_copy, 2 * blksz, SEEK_DATA) < 0 && errno == ENXIO);

        /* Test that the copied file has the correct size. */
        ASSERT_OK_ERRNO(fstat(fd_copy, &stat));
        assert_se(stat.st_size == 3 * blksz);

        close(fd);
        close(fd_copy);

        return 0;
}

TEST_RET(copy_holes_with_gaps) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF, fd_copy = -EBADF;
        struct stat st;
        off_t blksz;
        char *buf;
        int r;

        assert_se((tfd = mkdtemp_open(NULL, 0, &t)) >= 0);
        assert_se((fd = openat(tfd, "src", O_CREAT | O_RDWR, 0600)) >= 0);
        assert_se((fd_copy = openat(tfd, "dst", O_CREAT | O_WRONLY, 0600)) >= 0);

        ASSERT_OK_ERRNO(fstat(fd, &st));
        blksz = st.st_blksize;
        buf = alloca_safe(blksz);
        memset(buf, 1, blksz);

        /* Create a file with:
         *  - hole of 1 block
         *  - data of 2 block
         *  - hole of 2 blocks
         *  - data of 1 block
         *
         * Since sparse files are based on blocks and not bytes, we need to make
         * sure that the holes are aligned to the block size.
         */

        r = RET_NERRNO(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, blksz));
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return log_tests_skipped("Filesystem doesn't support hole punching");

        assert_se(lseek(fd, blksz, SEEK_CUR) >= 0);
        assert_se(loop_write(fd, buf, blksz) >= 0);
        assert_se(loop_write(fd, buf, blksz) >= 0);
        assert_se(lseek(fd, 2 * blksz, SEEK_CUR) >= 0);
        assert_se(loop_write(fd, buf, blksz) >= 0);
        assert_se(lseek(fd, 0, SEEK_SET) >= 0);
        assert_se(fsync(fd) >= 0);

        /* Copy to the start of the second hole */
        assert_se(copy_bytes(fd, fd_copy, 3 * blksz, COPY_HOLES) >= 0);
        ASSERT_OK_ERRNO(fstat(fd_copy, &st));
        assert_se(st.st_size == 3 * blksz);

        /* Copy to the middle of the second hole */
        assert_se(lseek(fd, 0, SEEK_SET) >= 0);
        assert_se(lseek(fd_copy, 0, SEEK_SET) >= 0);
        assert_se(ftruncate(fd_copy, 0) >= 0);
        assert_se(copy_bytes(fd, fd_copy, 4 * blksz, COPY_HOLES) >= 0);
        ASSERT_OK_ERRNO(fstat(fd_copy, &st));
        assert_se(st.st_size == 4 * blksz);

        /* Copy to the end of the second hole */
        assert_se(lseek(fd, 0, SEEK_SET) >= 0);
        assert_se(lseek(fd_copy, 0, SEEK_SET) >= 0);
        assert_se(ftruncate(fd_copy, 0) >= 0);
        assert_se(copy_bytes(fd, fd_copy, 5 * blksz, COPY_HOLES) >= 0);
        ASSERT_OK_ERRNO(fstat(fd_copy, &st));
        assert_se(st.st_size == 5 * blksz);

        /* Copy everything */
        assert_se(lseek(fd, 0, SEEK_SET) >= 0);
        assert_se(lseek(fd_copy, 0, SEEK_SET) >= 0);
        assert_se(ftruncate(fd_copy, 0) >= 0);
        assert_se(copy_bytes(fd, fd_copy, UINT64_MAX, COPY_HOLES) >= 0);
        ASSERT_OK_ERRNO(fstat(fd_copy, &st));
        assert_se(st.st_size == 6 * blksz);

        return 0;
}

TEST(copy_lock) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;

        assert_se((tfd = mkdtemp_open(NULL, 0, &t)) >= 0);
        assert_se(mkdirat(tfd, "abc", 0755) >= 0);
        assert_se(write_string_file_at(tfd, "abc/def", "abc", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se((fd = copy_directory_at(tfd, "abc", tfd, "qed", COPY_LOCK_BSD)) >= 0);
        assert_se(faccessat(tfd, "qed", F_OK, 0) >= 0);
        assert_se(faccessat(tfd, "qed/def", F_OK, 0) >= 0);
        assert_se(xopenat_lock(tfd, "qed", 0, LOCK_BSD, LOCK_EX|LOCK_NB) == -EAGAIN);
        fd = safe_close(fd);

        assert_se((fd = copy_file_at(tfd, "abc/def", tfd, "poi", 0, 0644, COPY_LOCK_BSD)));
        assert_se(read_file_at_and_streq(tfd, "poi", "abc\n"));
        assert_se(xopenat_lock(tfd, "poi", 0, LOCK_BSD, LOCK_EX|LOCK_NB) == -EAGAIN);
        fd = safe_close(fd);
}

TEST(copy_verify_linked) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd_1 = -EBADF, fd_2 = -EBADF;

        tfd = mkdtemp_open(NULL, O_PATH, &t);
        assert_se(tfd >= 0);

        assert_se(write_string_file_at(tfd, "hoge", "bar bar", WRITE_STRING_FILE_CREATE) >= 0);

        fd_1 = openat(tfd, "hoge", O_CLOEXEC | O_NOCTTY | O_RDONLY);
        assert_se(fd_1 >= 0);
        fd_2 = openat(tfd, "hoge", O_CLOEXEC | O_NOCTTY | O_RDONLY);
        assert_se(fd_2 >= 0);
        assert_se(unlinkat(tfd, "hoge", 0) >= 0);

        assert_se(copy_file_at(fd_1, NULL, tfd, "to_1", 0, 0644, 0) >= 0);
        assert_se(read_file_at_and_streq(tfd, "to_1", "bar bar\n"));

        assert_se(copy_file_at(fd_2, NULL, tfd, "to_2", O_EXCL, 0644, COPY_VERIFY_LINKED) == -EIDRM);
        assert_se(faccessat(tfd, "to_2", F_OK, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
