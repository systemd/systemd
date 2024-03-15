/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

        /* assume length of pathname is not greater than 40*/
        if (strlen(path) > 40)
                return -ENAMETOOLONG;

        if (!path_is_safe(path))
                return -ENOTDIR;

        /* assume a case where a specific label isn't allowed */
        if (path_equal(path, "/restricted_directory"))
                return -EACCES;
        return 0;
}

static int pre_labelling_func(int dir_fd, const char *path, mode_t mode) {
        int r;
        _cleanup_close_ int fd = -EBADF;

        assert(mode != MODE_INVALID);
        r = check_path(dir_fd, path);
        if (r < 0)
                return r;

        fd = openat(dir_fd, path, O_CLOEXEC|O_CREAT|O_RDWR|O_TRUNC, 0644);
        if (fd < 0 )
                return -errno;

        return 0;
}

static int post_labelling_func(int dir_fd, const char *path) {
       int r;

        /* assume label policies that restrict certain labels */
        r = check_path(dir_fd, path);
        if (r < 0)
                return r;

        /* Set file data to buf */
        if (fstatat(dir_fd, path, &buf, 0) != 0)
                return -errno;

        return 0; /* on success */
}

static int get_dir_fd(const char *dir_path) {
        int dir_fd = -EBADF;

        dir_fd = open_mkdir_at(AT_FDCWD, dir_path, O_CLOEXEC, 0775);
        if (dir_fd < 0)
                return -errno;

        return dir_fd;
}

static int labelling_op(int dir_fd, const char *text, const char *path, mode_t mode) {
        /* Write some content into the file */
        int r;
        ssize_t count;
        _cleanup_close_ int write_fd = -EBADF;

        /* Perform prelabelling operations */
        r = label_ops_pre(dir_fd, path, mode);
        if (r < 0)
                return -errno;

        /* Open the file within the directory for writing*/
        write_fd = openat(dir_fd, path, O_WRONLY|O_TRUNC, 0644);
        if (write_fd < 0)
                return -errno;

        /* Write data to the file*/
        count = write(write_fd, text, strlen(text));
        if (count < 0)
                return -errno;

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

static int fd = -EBADF;

TEST(label_ops_pre) {
        static const LabelOps test_label_ops = {
                .pre = pre_labelling_func,
                .post = NULL,
        };

        label_ops_reset();
        label_ops_set(&test_label_ops);
        fd = get_dir_fd("label_test_dir");
        assert_se(label_ops_pre(fd, "file1.txt", 0644) == 0);
        assert_se(label_ops_pre(fd, "/restricted_directory", 0644) == -EACCES);
        assert_se(label_ops_pre(fd, "", 0700) == -EINVAL);
        assert_se(label_ops_pre(fd, "wekrgoierhgoierhqgherhgwklegnlweehgorwfkryrit", 0644) == -ENAMETOOLONG);
}

TEST(label_ops_post) {
        const char *text1, *text2;
        static const LabelOps test_label_ops = {
                .pre = NULL,
                .post = post_labelling_func,
        };

        label_ops_reset();
        label_ops_set(&test_label_ops);

        /* Perform sample labelling operation */
        text1 = "Add initial texts to file for testing label operations\n";
        labelling_op(fd, text1, "file1.txt", 0644);
        assert_se(label_ops_post(fd, "file1.txt") == 0);
        assert_se(strlen(text1) == (size_t)buf.st_size);

        text2 = "Add text2 data to file\n";
        labelling_op(fd, text2, "file1.txt", 0644);
        assert_se(label_ops_post(fd, "file1.txt") == 0);
        assert_se(strlen(text2) == (size_t)buf.st_size);

        assert_se(label_ops_post(fd, "file2.txt") == -ENOENT);
        assert_se(label_ops_post(fd, "/abcd") == -ENOENT);
        assert_se(label_ops_post(fd, "/restricted_directory") == -EACCES);
        assert_se(label_ops_post(fd, "") == -EINVAL);
        safe_close(fd);
}

DEFINE_TEST_MAIN(LOG_INFO)
