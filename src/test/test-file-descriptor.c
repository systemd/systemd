/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "file-descriptor.h"
#include "macro-fundamental.h"
#include "string-util.h"
#include "tests.h"

static void set_file_descriptor(int fd, const char* fdname, FileDescriptor* ret) {
     *ret = (FileDescriptor) {
        .fd = fd,
        .fdname = fdname ? strdup(fdname) : NULL,
    };
}

TEST(file_descriptor_validate) {
        _cleanup_(file_descriptor_freep) FileDescriptor *fd_obj = NULL;
        int r;

        assert_se(fd_obj = new(FileDescriptor, 1));

        // Invalid FD
        set_file_descriptor(-1, "invalid_fd", fd_obj);
        r = file_descriptor_validate(fd_obj);
        assert_se(r == -EINVAL);
        free(fd_obj->fdname);

        // Invalid name = empty string
        set_file_descriptor(100, "", fd_obj);
        r = file_descriptor_validate(fd_obj);
        assert_se(r == -EINVAL);
        free(fd_obj->fdname);

        // Invalid name = NULL
        set_file_descriptor(100, NULL, fd_obj);
        r = file_descriptor_validate(fd_obj);
        assert_se(r == -EINVAL);

        // Colon in name
        set_file_descriptor(100, "test:", fd_obj);
        r = file_descriptor_validate(fd_obj);
        assert_se(r == -EINVAL);
}

TEST(file_descriptor_to_string) {
        _cleanup_(file_descriptor_freep) FileDescriptor *fd_obj = NULL;
        _cleanup_free_ char *fd_str = NULL;
        int r;

        assert_se(fd_obj = new(FileDescriptor, 1));

        set_file_descriptor(100, "stdin", fd_obj);
        r = file_descriptor_validate(fd_obj);
        assert_se(r >= 0);
        r = file_descriptor_to_string(fd_obj, &fd_str);
        assert_se(r >= 0);
        ASSERT_STREQ(fd_str, "100:stdin");
}

DEFINE_TEST_MAIN(LOG_INFO);
