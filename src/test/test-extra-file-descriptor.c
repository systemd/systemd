/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "extra-file-descriptor.h"
#include "macro.h"
#include "tests.h"

static void set_file_descriptor(int fd, const char *fdname, ExtraFileDescriptor *ret) {
        *ret = (ExtraFileDescriptor) {
                .fd = fd,
                .fdname = fdname ? strdup(fdname) : NULL,
        };
}

static ExtraFileDescriptor* test_extra_file_descriptor_free(ExtraFileDescriptor *extra_fd) {
        /* This test uses fake file descriptor numbers so ensure the test doesn't really try
         * to close them by assigning -EBADF before calling free. */
        extra_fd->fd = -EBADF;
        return extra_file_descriptor_free(extra_fd);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ExtraFileDescriptor*, test_extra_file_descriptor_free);

TEST(file_descriptor_validate) {
        _cleanup_(test_extra_file_descriptor_freep) ExtraFileDescriptor *extra_fd = NULL;
        int r;

        ASSERT_RETURN_EXPECTED_SE(extra_fd = new(ExtraFileDescriptor, 1));

        /* Invalid FD */
        set_file_descriptor(-1, "invalid_fd", extra_fd);
        r = extra_file_descriptor_validate(extra_fd);
        ASSERT_EQ(r, -EINVAL);
        free(extra_fd->fdname);

        /* Invalid name = empty string */
        set_file_descriptor(100, "", extra_fd);
        r = extra_file_descriptor_validate(extra_fd);
        ASSERT_EQ(r, -EINVAL);
        free(extra_fd->fdname);

        /* Invalid name = NULL */
        set_file_descriptor(100, NULL, extra_fd);
        r = extra_file_descriptor_validate(extra_fd);
        ASSERT_EQ(r, -EINVAL);

        /* Colon in name */
        set_file_descriptor(100, "test:", extra_fd);
        r = extra_file_descriptor_validate(extra_fd);
        ASSERT_EQ(r, -EINVAL);
}

TEST(file_descriptor_to_string) {
        _cleanup_(test_extra_file_descriptor_freep) ExtraFileDescriptor *extra_fd = NULL;
        _cleanup_free_ char *fd_str = NULL;
        int r;

        ASSERT_RETURN_EXPECTED_SE(extra_fd = new(ExtraFileDescriptor, 1));

        set_file_descriptor(100, "stdin", extra_fd);
        r = extra_file_descriptor_validate(extra_fd);
        ASSERT_GE(r, 0);
        r = extra_file_descriptor_to_string(extra_fd, &fd_str);
        ASSERT_GE(r, 0);
        ASSERT_STREQ(fd_str, "100:stdin");
}

DEFINE_TEST_MAIN(LOG_INFO);
