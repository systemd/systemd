/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>

#include "alloc-util.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "util.h"

static void test_copy_file(void) {
        _cleanup_free_ char *buf = NULL;
        char fn[] = "/tmp/test-copy_file.XXXXXX";
        char fn_copy[] = "/tmp/test-copy_file.XXXXXX";
        size_t sz = 0;
        int fd;

        log_info("%s", __func__);

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);
        close(fd);

        fd = mkostemp_safe(fn_copy);
        assert_se(fd >= 0);
        close(fd);

        assert_se(write_string_file(fn, "foo bar bar bar foo", WRITE_STRING_FILE_CREATE) == 0);

        assert_se(copy_file(fn, fn_copy, 0, 0644, 0, 0, COPY_REFLINK) == 0);

        assert_se(read_full_file(fn_copy, &buf, &sz) == 0);
        assert_se(streq(buf, "foo bar bar bar foo\n"));
        assert_se(sz == 20);

        unlink(fn);
        unlink(fn_copy);
}

static void test_copy_file_fd(void) {
        char in_fn[] = "/tmp/test-copy-file-fd-XXXXXX";
        char out_fn[] = "/tmp/test-copy-file-fd-XXXXXX";
        _cleanup_close_ int in_fd = -1, out_fd = -1;
        const char *text = "boohoo\nfoo\n\tbar\n";
        char buf[64] = {};

        log_info("%s", __func__);

        in_fd = mkostemp_safe(in_fn);
        assert_se(in_fd >= 0);
        out_fd = mkostemp_safe(out_fn);
        assert_se(out_fd >= 0);

        assert_se(write_string_file(in_fn, text, WRITE_STRING_FILE_CREATE) == 0);
        assert_se(copy_file_fd("/a/file/which/does/not/exist/i/guess", out_fd, COPY_REFLINK) < 0);
        assert_se(copy_file_fd(in_fn, out_fd, COPY_REFLINK) >= 0);
        assert_se(lseek(out_fd, SEEK_SET, 0) == 0);

        assert_se(read(out_fd, buf, sizeof buf) == (ssize_t) strlen(text));
        assert_se(streq(buf, text));

        unlink(in_fn);
        unlink(out_fn);
}

static void test_copy_tree(void) {
        char original_dir[] = "/tmp/test-copy_tree/";
        char copy_dir[] = "/tmp/test-copy_tree-copy/";
        char **files = STRV_MAKE("file", "dir1/file", "dir1/dir2/file", "dir1/dir2/dir3/dir4/dir5/file");
        char **links = STRV_MAKE("link", "file",
                                 "link2", "dir1/file");
        char **p, **link;
        const char *unixsockp;
        struct stat st;

        log_info("%s", __func__);

        (void) rm_rf(copy_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf(original_dir, REMOVE_ROOT|REMOVE_PHYSICAL);

        STRV_FOREACH(p, files) {
                _cleanup_free_ char *f;

                assert_se(f = path_join(original_dir, *p));

                assert_se(mkdir_parents(f, 0755) >= 0);
                assert_se(write_string_file(f, "file", WRITE_STRING_FILE_CREATE) == 0);
        }

        STRV_FOREACH_PAIR(link, p, links) {
                _cleanup_free_ char *f, *l;

                assert_se(f = path_join(original_dir, *p));
                assert_se(l = path_join(original_dir, *link));

                assert_se(mkdir_parents(l, 0755) >= 0);
                assert_se(symlink(f, l) == 0);
        }

        unixsockp = strjoina(original_dir, "unixsock");
        assert_se(mknod(unixsockp, S_IFSOCK|0644, 0) >= 0);

        assert_se(copy_tree(original_dir, copy_dir, UID_INVALID, GID_INVALID, COPY_REFLINK|COPY_MERGE) == 0);

        STRV_FOREACH(p, files) {
                _cleanup_free_ char *buf, *f;
                size_t sz;

                assert_se(f = path_join(copy_dir, *p));

                assert_se(access(f, F_OK) == 0);
                assert_se(read_full_file(f, &buf, &sz) == 0);
                assert_se(streq(buf, "file\n"));
        }

        STRV_FOREACH_PAIR(link, p, links) {
                _cleanup_free_ char *target, *f, *l;

                assert_se(f = strjoin(original_dir, *p));
                assert_se(l = strjoin(copy_dir, *link));

                assert_se(chase_symlinks(l, NULL, 0, &target) == 1);
                assert_se(path_equal(f, target));
        }

        unixsockp = strjoina(copy_dir, "unixsock");
        assert_se(stat(unixsockp, &st) >= 0);
        assert_se(S_ISSOCK(st.st_mode));

        assert_se(copy_tree(original_dir, copy_dir, UID_INVALID, GID_INVALID, COPY_REFLINK) < 0);
        assert_se(copy_tree("/tmp/inexistent/foo/bar/fsdoi", copy_dir, UID_INVALID, GID_INVALID, COPY_REFLINK) < 0);

        (void) rm_rf(copy_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf(original_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_copy_bytes(void) {
        _cleanup_close_pair_ int pipefd[2] = {-1, -1};
        _cleanup_close_ int infd = -1;
        int r, r2;
        char buf[1024], buf2[1024];

        infd = open("/usr/lib/os-release", O_RDONLY|O_CLOEXEC);
        if (infd < 0)
                infd = open("/etc/os-release", O_RDONLY|O_CLOEXEC);
        assert_se(infd >= 0);

        assert_se(pipe2(pipefd, O_CLOEXEC) == 0);

        r = copy_bytes(infd, pipefd[1], (uint64_t) -1, 0);
        assert_se(r == 0);

        r = read(pipefd[0], buf, sizeof(buf));
        assert_se(r >= 0);

        assert_se(lseek(infd, 0, SEEK_SET) == 0);
        r2 = read(infd, buf2, sizeof(buf2));
        assert_se(r == r2);

        assert_se(strneq(buf, buf2, r));

        /* test copy_bytes with invalid descriptors */
        r = copy_bytes(pipefd[0], pipefd[0], 1, 0);
        assert_se(r == -EBADF);

        r = copy_bytes(pipefd[1], pipefd[1], 1, 0);
        assert_se(r == -EBADF);

        r = copy_bytes(pipefd[1], infd, 1, 0);
        assert_se(r == -EBADF);
}

static void test_copy_bytes_regular_file(const char *src, bool try_reflink, uint64_t max_bytes) {
        char fn2[] = "/tmp/test-copy-file-XXXXXX";
        char fn3[] = "/tmp/test-copy-file-XXXXXX";
        _cleanup_close_ int fd = -1, fd2 = -1, fd3 = -1;
        int r;
        struct stat buf, buf2, buf3;

        log_info("%s try_reflink=%s max_bytes=%" PRIu64, __func__, yes_no(try_reflink), max_bytes);

        fd = open(src, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        assert_se(fd >= 0);

        fd2 = mkostemp_safe(fn2);
        assert_se(fd2 >= 0);

        fd3 = mkostemp_safe(fn3);
        assert_se(fd3 >= 0);

        r = copy_bytes(fd, fd2, max_bytes, try_reflink ? COPY_REFLINK : 0);
        if (max_bytes == (uint64_t) -1)
                assert_se(r == 0);
        else
                assert_se(IN_SET(r, 0, 1));

        assert_se(fstat(fd, &buf) == 0);
        assert_se(fstat(fd2, &buf2) == 0);
        assert_se((uint64_t) buf2.st_size == MIN((uint64_t) buf.st_size, max_bytes));

        if (max_bytes < (uint64_t) -1)
                /* Make sure the file is now higher than max_bytes */
                assert_se(ftruncate(fd2, max_bytes + 1) == 0);

        assert_se(lseek(fd2, 0, SEEK_SET) == 0);

        r = copy_bytes(fd2, fd3, max_bytes, try_reflink ? COPY_REFLINK : 0);
        if (max_bytes == (uint64_t) -1)
                assert_se(r == 0);
        else
                /* We cannot distinguish between the input being exactly max_bytes
                 * or longer than max_bytes (without trying to read one more byte,
                 * or calling stat, or FION_READ, etc, and we don't want to do any
                 * of that). So we expect "truncation" since we know that file we
                 * are copying is exactly max_bytes bytes. */
                assert_se(r == 1);

        assert_se(fstat(fd3, &buf3) == 0);

        if (max_bytes == (uint64_t) -1)
                assert_se(buf3.st_size == buf2.st_size);
        else
                assert_se((uint64_t) buf3.st_size == max_bytes);

        unlink(fn2);
        unlink(fn3);
}

static void test_copy_atomic(void) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        const char *q;
        int r;

        assert_se(mkdtemp_malloc(NULL, &p) >= 0);

        q = strjoina(p, "/fstab");

        r = copy_file_atomic("/etc/fstab", q, 0644, 0, 0, COPY_REFLINK);
        if (r == -ENOENT)
                return;

        assert_se(copy_file_atomic("/etc/fstab", q, 0644, 0, 0, COPY_REFLINK) == -EEXIST);

        assert_se(copy_file_atomic("/etc/fstab", q, 0644, 0, 0, COPY_REPLACE) >= 0);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_copy_file();
        test_copy_file_fd();
        test_copy_tree();
        test_copy_bytes();
        test_copy_bytes_regular_file(argv[0], false, (uint64_t) -1);
        test_copy_bytes_regular_file(argv[0], true, (uint64_t) -1);
        test_copy_bytes_regular_file(argv[0], false, 1000); /* smaller than copy buffer size */
        test_copy_bytes_regular_file(argv[0], true, 1000);
        test_copy_bytes_regular_file(argv[0], false, 32000); /* larger than copy buffer size */
        test_copy_bytes_regular_file(argv[0], true, 32000);
        test_copy_atomic();

        return 0;
}
