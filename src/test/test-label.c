/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "label.h"
#include "string-util.h"
#include "tests.h"


int pre_labelling_func(int dir_fd, const char *path, mode_t mode);
int post_labelling_func(int dir_fd, const char *path);
LabelOps test_label_ops = {
        .pre = NULL,
        .post = NULL
    };

TEST(label_ops_set) {

    assert_se(label_ops_set(&test_label_ops) == 0);

    /*attempt to reset label_ops when already set*/
    assert_se(label_ops_set(&test_label_ops) == -EBUSY);

}

int pre_labelling_func(int dir_fd, const char *path, mode_t mode) {
    /*sample pre_labelling task*/
    if (dir_fd < 0 || !path || mode == 0)
        return -1;

    /*assume a case where a specific label isn't allowed*/
    if (streq(path, "/restricted_directory"))
        return -1;

    /* custom pre labelling logic here */
    return 0; /* on success */

}

TEST(label_ops_pre) {

    assert_se(label_ops_pre(1, "abcd", 0755) == 0);
    test_label_ops.pre = pre_labelling_func;
    assert_se(label_ops_pre(1, "abcd", 0755) == 0);
    assert_se(label_ops_pre(1, "/restricted_directory", 0755) == -1);
    assert_se(label_ops_pre(1, "abcd", 0) == -1);

}

int post_labelling_func(int dir_fd, const char *path) {
    /*sample post_labelling task*/

    if (dir_fd < 0 || !path)
    return -1;

    /*assume label policies that restrict certain labels*/
    if (strlen(path) > 100 || streq(path, "/restricted_directory"))
        return -1;

    /* custom post labelling logic */
    return 0; /*on sucess*/

}

TEST(label_ops_post) {

    assert_se(label_ops_post(1, "abcd") == 0);
    test_label_ops.post = post_labelling_func;
    assert_se(label_ops_post(1, "abc") == 0);
    assert_se(label_ops_post(1, "/restricted_directory") == -1);
    label_ops_set(NULL);
}

DEFINE_TEST_MAIN(LOG_INFO)
