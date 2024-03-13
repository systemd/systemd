/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "fs-util.h"
#include "label.h"
#include "path-util.h"
#include "string-util.h"
#include "tests.h"


static int check_path(int dir_fd, const char *path) {

        assert(dir_fd >= 0);
        assert(path);

        if (!is_path(path) || !path_is_valid(path) || isempty(path))
                return -EINVAL;

        if (strlen(path) > 40)
                return -ENAMETOOLONG;

        if (!path_is_safe(path))
                return -ENOTDIR;

        /*assume a case where a specific label isn't allowed*/
        if (path_equal(path, "/restricted_directory"))
                return -EACCES;
        return 0;
}
static int pre_labelling_func(int dir_fd, const char *path, mode_t mode) {
        int ret;

        assert(mode != MODE_INVALID);
        /*sample pre_labelling task*/

        ret = check_path(dir_fd, path);
        if (ret < 0) {
                return ret;
        }

        /* custom pre labelling logic here */
        return 0; /* on success */
}

static int post_labelling_func(int dir_fd, const char *path) {
        /*sample post_labelling task*/
       int ret;

        /*assume label policies that restrict certain labels*/

        ret = check_path(dir_fd, path);
        if (ret < 0) {
                return ret;
        }

        /* custom post labelling logic */
        return 0; /*on sucess*/
}

TEST(label_ops_set) {

        static const LabelOps test_label_ops = {
        .pre = NULL,
        .post = NULL,
    };

        assert_se(label_ops_set(&test_label_ops) == 0);
        /*attempt to reset label_ops when already set*/
        assert_se(label_ops_set(&test_label_ops) == -EBUSY);
}

TEST(label_ops_pre) {

        static const LabelOps test_label_ops = {
                .pre = pre_labelling_func,
                .post = post_labelling_func,
        };

        label_ops_set(&test_label_ops);


        assert_se(label_ops_pre(1, "/abcd", 0755) == 0);
        assert_se(label_ops_pre(1, "/restricted_directory", 0755) == -EACCES);
        assert_se(label_ops_pre(2, "abcd", 0644) == -EINVAL);
        assert_se(label_ops_pre(1, "/wekrgoierhgoierhqgherhgwklegnlweehgorwfkryrit", 0755) == -ENAMETOOLONG);
}

TEST(label_ops_post) {

        static const LabelOps test_label_ops = {
                .pre = pre_labelling_func,
                .post = post_labelling_func,
        };
        label_ops_set(&test_label_ops);
        assert_se(label_ops_post(1, "/abcd") == 0);
        assert_se(label_ops_post(1, "/restricted_directory") == -EACCES);
        assert_se(label_ops_post(2, "") == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO)
