/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "sd-gpt.h"

#include "errno-util.h"
#include "fd-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "validatefs-util.h"
#include "xattr-util.h"

static int make_dir(char **ret_path, int *ret_fd) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = mkdtemp_open("/var/tmp/test-validatefsXXXXXX", O_RDONLY|O_CLOEXEC, &t);
        if (fd < 0)
                return fd;

        r = xsetxattr(fd, /* path= */ NULL, AT_EMPTY_PATH, "user.test", "x");
        if (r < 0)
                return r;

        *ret_path = TAKE_PTR(t);
        *ret_fd = TAKE_FD(fd);
        return 0;
}

#define PREPARE_DIR(t, fd)                                                                      \
        do {                                                                                    \
                int _r = make_dir(&(t), &(fd));                                                 \
                if (ERRNO_IS_NEG_NOT_SUPPORTED(_r))                                             \
                        return (void) log_tests_skipped_errno(_r, "no xattrs supported on /var/tmp"); \
                ASSERT_OK(_r);                                                                  \
        } while (false)

TEST(read_none) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_(validate_fields_done) ValidateFields f = {};

        PREPARE_DIR(t, fd);

        ASSERT_OK_ZERO(validate_fields_read(fd, LOG_DEBUG, &f));
        ASSERT_FALSE(validate_fields_need_gpt(&f));

        /* No constraints means everything passes */
        ASSERT_OK(validate_fields_check_mount_point(&f, /* root= */ NULL, "/foo", LOG_DEBUG));
        ASSERT_OK(validate_fields_check_gpt_label(&f, NULL, LOG_DEBUG));
        ASSERT_OK(validate_fields_check_gpt_type(&f, NULL, LOG_DEBUG));
}

TEST(read_and_check) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_(validate_fields_done) ValidateFields f = {};

        PREPARE_DIR(t, fd);

        ASSERT_OK(xsetxattr_strv(fd, NULL, AT_EMPTY_PATH, "user.validatefs.gpt_type_uuid",
                                 STRV_MAKE(SD_ID128_TO_UUID_STRING(SD_GPT_HOME), SD_ID128_TO_UUID_STRING(SD_GPT_SRV))));
        ASSERT_OK(xsetxattr_strv(fd, NULL, AT_EMPTY_PATH, "user.validatefs.gpt_label", STRV_MAKE("foo", "bar")));
        ASSERT_OK(xsetxattr_strv(fd, NULL, AT_EMPTY_PATH, "user.validatefs.mount_point", STRV_MAKE("/home", "/srv")));

        ASSERT_OK_POSITIVE(validate_fields_read(fd, LOG_DEBUG, &f));
        ASSERT_TRUE(validate_fields_need_gpt(&f));
        ASSERT_EQ(f.n_gpt_type_uuid, 2U);
        ASSERT_TRUE(sd_id128_equal(f.gpt_type_uuid[0], SD_GPT_HOME));
        ASSERT_TRUE(sd_id128_equal(f.gpt_type_uuid[1], SD_GPT_SRV));
        ASSERT_TRUE(strv_equal(f.gpt_label, STRV_MAKE("foo", "bar")));
        ASSERT_TRUE(strv_equal(f.mount_point, STRV_MAKE("/home", "/srv")));

        ASSERT_OK(validate_fields_check_mount_point(&f, /* root= */ NULL, "/home", LOG_DEBUG));
        ASSERT_OK(validate_fields_check_mount_point(&f, /* root= */ NULL, "/srv", LOG_DEBUG));
        ASSERT_OK(validate_fields_check_mount_point(&f, /* root= */ NULL, "//home/", LOG_DEBUG));
        ASSERT_ERROR(validate_fields_check_mount_point(&f, /* root= */ NULL, "/", LOG_DEBUG), EPERM);
        ASSERT_ERROR(validate_fields_check_mount_point(&f, /* root= */ NULL, "/usr", LOG_DEBUG), EPERM);
        ASSERT_OK(validate_fields_check_mount_point(&f, "/sysroot", "/sysroot/home", LOG_DEBUG));
        ASSERT_ERROR(validate_fields_check_mount_point(&f, "/sysroot", "/home", LOG_DEBUG), EPERM);

        ASSERT_OK(validate_fields_check_gpt_label(&f, "foo", LOG_DEBUG));
        ASSERT_OK(validate_fields_check_gpt_label(&f, "bar", LOG_DEBUG));
        ASSERT_ERROR(validate_fields_check_gpt_label(&f, "baz", LOG_DEBUG), EPERM);
        ASSERT_ERROR(validate_fields_check_gpt_label(&f, "", LOG_DEBUG), EPERM);
        ASSERT_ERROR(validate_fields_check_gpt_label(&f, NULL, LOG_DEBUG), EPERM);

        ASSERT_OK(validate_fields_check_gpt_type(&f, &SD_GPT_HOME, LOG_DEBUG));
        ASSERT_OK(validate_fields_check_gpt_type(&f, &SD_GPT_SRV, LOG_DEBUG));
        ASSERT_ERROR(validate_fields_check_gpt_type(&f, &SD_GPT_VAR, LOG_DEBUG), EPERM);
        ASSERT_ERROR(validate_fields_check_gpt_type(&f, NULL, LOG_DEBUG), EPERM);
}

TEST(read_empty_label) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_(validate_fields_done) ValidateFields f = {};

        PREPARE_DIR(t, fd);

        ASSERT_OK(xsetxattr_strv(fd, NULL, AT_EMPTY_PATH, "user.validatefs.gpt_label", STRV_MAKE("")));

        ASSERT_OK_POSITIVE(validate_fields_read(fd, LOG_DEBUG, &f));
        ASSERT_TRUE(validate_fields_need_gpt(&f));

        /* An empty label constraint is fulfilled by an unlabelled partition */
        ASSERT_OK(validate_fields_check_gpt_label(&f, NULL, LOG_DEBUG));
        ASSERT_OK(validate_fields_check_gpt_label(&f, "", LOG_DEBUG));
        ASSERT_ERROR(validate_fields_check_gpt_label(&f, "foo", LOG_DEBUG), EPERM);
}

static void test_read_invalid_one(const char *name, char * const *l) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_(validate_fields_done) ValidateFields f = {};

        log_debug("/* %s(%s) */", __func__, name);

        PREPARE_DIR(t, fd);

        ASSERT_OK(xsetxattr_strv(fd, NULL, AT_EMPTY_PATH, name, l));
        ASSERT_ERROR(validate_fields_read(fd, LOG_DEBUG, &f), EINVAL);
}

TEST(read_invalid) {
        test_read_invalid_one("user.validatefs.gpt_type_uuid", STRV_MAKE("nouuid"));
        test_read_invalid_one("user.validatefs.gpt_type_uuid", STRV_MAKE(SD_ID128_TO_UUID_STRING(SD_GPT_HOME), "nouuid"));
        test_read_invalid_one("user.validatefs.gpt_label", STRV_MAKE("foo\nbar"));
        test_read_invalid_one("user.validatefs.gpt_label", STRV_MAKE("foo\xff"));
        test_read_invalid_one("user.validatefs.mount_point", STRV_MAKE("relative"));
        test_read_invalid_one("user.validatefs.mount_point", STRV_MAKE("/foo/../bar"));
        test_read_invalid_one("user.validatefs.mount_point", STRV_MAKE("/foo", "/b\tar"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
