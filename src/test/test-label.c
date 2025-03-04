/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "label.h"
#include "path-util.h"
#include "string-util.h"
#include "tests.h"

static struct stat buf;
static int check_path(int dir_fd, const char *path) {
        assert(path);
        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        if (isempty(path))
                return -EINVAL;

        /* assume length of pathname is not greater than 40 */
        if (strlen(path) > 40)
                return -ENAMETOOLONG;

        /* assume a case where a specific label isn't allowed */
        if (path_equal(path, "/restricted_directory"))
                return -EACCES;
        return 0;
}

static int pre_labelling_func(int dir_fd, const char *path, mode_t mode) {
        int r;

        assert(mode != MODE_INVALID);
        r = check_path(dir_fd, path);
        if (r < 0)
                return log_error_errno(r, "Error in pathname =>: %m");

        return 0;
}

static int post_labelling_func(int dir_fd, const char *path, bool created) {
       int r;

        /* assume label policies that restrict certain labels */
        r = check_path(dir_fd, path);
        if (r < 0)
                return log_error_errno(r, "Error in pathname =>: %m");

        /* Set file data to buf */
        r = RET_NERRNO(fstatat(dir_fd, path, &buf, 0));
        if (r < 0)
                return log_error_errno(r, "Error in getting file status =>: %m");

        return 0; /* on success */
}

static int get_dir_fd(const char *dir_path, mode_t mode) {
        /* create a new directory and return its descriptor */
        int dir_fd = -EBADF;

        assert(dir_path);
        dir_fd = RET_NERRNO(open_mkdir_at(AT_FDCWD, dir_path, O_CLOEXEC, mode));
        if (dir_fd < 0)
                return log_error_errno(dir_fd, "Error occurred while opening directory =>: %m");

        return dir_fd;
}

static int labelling_op(int dir_fd, const char *text, const char *path, mode_t mode) {
        /* Write some content into the file */
        ssize_t count;
        _cleanup_close_ int write_fd = -EBADF;
        int r;

        assert(text);
        assert(mode != MODE_INVALID);
        r = check_path(dir_fd, path);
        if (r < 0)
                return log_error_errno(r, "Error in pathname =>: %m");

        /* Open the file within the directory for writing */
        write_fd = RET_NERRNO(openat(dir_fd, path, O_CLOEXEC|O_WRONLY|O_TRUNC|O_CREAT, 0644));
        if (write_fd < 0)
                return log_error_errno(write_fd, "Error in opening directory for writing =>: %m");

        /* Write data to the file */
        count = RET_NERRNO(write(write_fd, text, strlen(text)));
        if (count < 0)
                return log_error_errno(count, "Error occurred while opening file for writing =>: %m");
        return 0;
}

TEST(label_ops_set) {
        static const LabelOps test_label_ops = {
                .pre = NULL,
                .post = NULL,
        };

        label_ops_reset();
        assert_se(label_ops_set(&test_label_ops) == 0);
        /* attempt to reset label_ops when already set */
        assert_se(label_ops_set(&test_label_ops) == -EBUSY);
}

TEST(label_ops_pre) {
        _cleanup_close_ int fd;
        static const LabelOps test_label_ops = {
                .pre = pre_labelling_func,
                .post = NULL,
        };

        label_ops_reset();
        label_ops_set(&test_label_ops);
        fd = get_dir_fd("file1.txt", 0755);
        assert_se(label_ops_pre(fd, "file1.txt", 0644) == 0);
        assert_se(label_ops_pre(fd, "/restricted_directory", 0644) == -EACCES);
        assert_se(label_ops_pre(fd, "", 0700) == -EINVAL);
        assert_se(label_ops_pre(fd, "/tmp", 0700) == 0);
        assert_se(label_ops_pre(fd, "wekrgoierhgoierhqgherhgwklegnlweehgorwfkryrit", 0644) == -ENAMETOOLONG);
}

TEST(label_ops_post) {
        _cleanup_close_ int fd = -EBADF;
        const char *text1, *text2;
        static const LabelOps test_label_ops = {
                .pre = NULL,
                .post = post_labelling_func,
        };

        label_ops_reset();
        label_ops_set(&test_label_ops);

        /* Open directory */
        fd = RET_NERRNO(get_dir_fd("label_test_dir", 0755));
        text1 = "Add initial texts to file for testing label operations to file1\n";

        assert(labelling_op(fd, text1, "file1.txt", 0644) == 0);
        assert_se(label_ops_post(fd, "file1.txt", true) == 0);
        assert_se(strlen(text1) == (size_t)buf.st_size);
        text2 = "Add text2 data to file2\n";

        assert(labelling_op(fd, text2, "file2.txt", 0644) == 0);
        assert_se(label_ops_post(fd, "file2.txt", true) == 0);
        assert_se(strlen(text2) == (size_t)buf.st_size);
        assert_se(label_ops_post(fd, "file3.txt", true) == -ENOENT);
        assert_se(label_ops_post(fd, "/abcd", true) == -ENOENT);
        assert_se(label_ops_post(fd, "/restricted_directory", true) == -EACCES);
        assert_se(label_ops_post(fd, "", true) == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO)
