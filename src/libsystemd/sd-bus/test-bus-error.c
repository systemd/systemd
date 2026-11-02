/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "errno-list.h"
#include "errno-util.h"
#include "string-util.h"
#include "tests.h"

TEST(error) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL, second = SD_BUS_ERROR_NULL;
        const sd_bus_error const_error = SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_FILE_EXISTS, "const error");
        const sd_bus_error temporarily_const_error = {
                .name = SD_BUS_ERROR_ACCESS_DENIED,
                .message = "oh! no",
                ._need_free = -1,
        };

        ASSERT_FALSE(sd_bus_error_is_set(&error));
        ASSERT_ERROR(sd_bus_error_set(&error, SD_BUS_ERROR_NOT_SUPPORTED, "xxx"), EOPNOTSUPP);
        ASSERT_STREQ(error.name, SD_BUS_ERROR_NOT_SUPPORTED);
        ASSERT_STREQ(error.message, "xxx");
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_NOT_SUPPORTED));
        ASSERT_TRUE(sd_bus_error_has_names_sentinel(&error, SD_BUS_ERROR_NOT_SUPPORTED, NULL));
        ASSERT_TRUE(sd_bus_error_has_names(&error, SD_BUS_ERROR_NOT_SUPPORTED));
        ASSERT_TRUE(sd_bus_error_has_names(&error, SD_BUS_ERROR_NOT_SUPPORTED, SD_BUS_ERROR_FILE_NOT_FOUND));
        ASSERT_TRUE(sd_bus_error_has_names(&error, SD_BUS_ERROR_FILE_NOT_FOUND, SD_BUS_ERROR_NOT_SUPPORTED, NULL));
        ASSERT_FALSE(sd_bus_error_has_names(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        ASSERT_EQ(sd_bus_error_get_errno(&error), EOPNOTSUPP);
        ASSERT_TRUE(sd_bus_error_is_set(&error));
        sd_bus_error_free(&error);

        /* Check with no error */
        ASSERT_FALSE(sd_bus_error_is_set(&error));
        ASSERT_OK_ZERO(sd_bus_error_setf(&error, /* name= */ NULL, "yyy %i", -1));
        ASSERT_NULL(error.name);
        ASSERT_NULL(error.message);
        ASSERT_FALSE(sd_bus_error_has_name(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        ASSERT_FALSE(sd_bus_error_has_names(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        ASSERT_EQ(sd_bus_error_get_errno(&error), 0);
        ASSERT_FALSE(sd_bus_error_is_set(&error));

        ASSERT_ERROR(sd_bus_error_setf(&error, SD_BUS_ERROR_FILE_NOT_FOUND, "yyy %i", -1), ENOENT);
        ASSERT_STREQ(error.name, SD_BUS_ERROR_FILE_NOT_FOUND);
        ASSERT_STREQ(error.message, "yyy -1");
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        ASSERT_TRUE(sd_bus_error_has_names(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        ASSERT_EQ(sd_bus_error_get_errno(&error), ENOENT);
        ASSERT_TRUE(sd_bus_error_is_set(&error));

        ASSERT_FALSE(sd_bus_error_is_set(&second));
        ASSERT_EQ(second._need_free, 0);
        ASSERT_GT(error._need_free, 0);
        ASSERT_ERROR(sd_bus_error_copy(&second, &error), ENOENT);
        ASSERT_GT(second._need_free, 0);
        ASSERT_STREQ(error.name, second.name);
        ASSERT_STREQ(error.message, second.message);
        ASSERT_EQ(sd_bus_error_get_errno(&second), ENOENT);
        ASSERT_TRUE(sd_bus_error_has_name(&second, SD_BUS_ERROR_FILE_NOT_FOUND));
        ASSERT_TRUE(sd_bus_error_has_names(&second, SD_BUS_ERROR_FILE_NOT_FOUND));
        ASSERT_TRUE(sd_bus_error_is_set(&second));

        sd_bus_error_free(&error);
        sd_bus_error_free(&second);

        ASSERT_FALSE(sd_bus_error_is_set(&second));
        ASSERT_EQ(const_error._need_free, 0);
        ASSERT_ERROR(sd_bus_error_copy(&second, &const_error), EEXIST);
        ASSERT_EQ(second._need_free, 0);
        ASSERT_STREQ(const_error.name, second.name);
        ASSERT_STREQ(const_error.message, second.message);
        ASSERT_EQ(sd_bus_error_get_errno(&second), EEXIST);
        ASSERT_TRUE(sd_bus_error_has_name(&second, SD_BUS_ERROR_FILE_EXISTS));
        ASSERT_TRUE(sd_bus_error_is_set(&second));
        sd_bus_error_free(&second);

        ASSERT_FALSE(sd_bus_error_is_set(&second));
        ASSERT_LT(temporarily_const_error._need_free, 0);
        ASSERT_ERROR(sd_bus_error_copy(&second, &temporarily_const_error), EACCES);
        ASSERT_GT(second._need_free, 0);
        ASSERT_STREQ(temporarily_const_error.name, second.name);
        ASSERT_STREQ(temporarily_const_error.message, second.message);
        ASSERT_EQ(sd_bus_error_get_errno(&second), EACCES);
        ASSERT_TRUE(sd_bus_error_has_name(&second, SD_BUS_ERROR_ACCESS_DENIED));
        ASSERT_TRUE(sd_bus_error_is_set(&second));

        ASSERT_FALSE(sd_bus_error_is_set(&error));
        ASSERT_ERROR(sd_bus_error_set_const(&error, "System.Error.EUCLEAN", "Hallo"), EUCLEAN);
        ASSERT_STREQ(error.name, "System.Error.EUCLEAN");
        ASSERT_STREQ(error.message, "Hallo");
        ASSERT_TRUE(sd_bus_error_has_name(&error, "System.Error.EUCLEAN"));
        ASSERT_EQ(sd_bus_error_get_errno(&error), EUCLEAN);
        ASSERT_TRUE(sd_bus_error_is_set(&error));
        sd_bus_error_free(&error);

        ASSERT_FALSE(sd_bus_error_is_set(&error));
        ASSERT_ERROR(sd_bus_error_set_errno(&error, EBUSY), EBUSY);
        ASSERT_STREQ(error.name, "System.Error.EBUSY");
        ASSERT_STREQ(error.message, STRERROR(EBUSY));
        ASSERT_TRUE(sd_bus_error_has_name(&error, "System.Error.EBUSY"));
        ASSERT_EQ(sd_bus_error_get_errno(&error), EBUSY);
        ASSERT_TRUE(sd_bus_error_is_set(&error));
        sd_bus_error_free(&error);

        ASSERT_FALSE(sd_bus_error_is_set(&error));
        ASSERT_ERROR(sd_bus_error_set_errnof(&error, EIO, "Waldi %c", 'X'), EIO);
        ASSERT_STREQ(error.name, SD_BUS_ERROR_IO_ERROR);
        ASSERT_STREQ(error.message, "Waldi X");
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_IO_ERROR));
        ASSERT_EQ(sd_bus_error_get_errno(&error), EIO);
        ASSERT_TRUE(sd_bus_error_is_set(&error));
        sd_bus_error_free(&error);

        /* Check with no error */
        ASSERT_FALSE(sd_bus_error_is_set(&error));
        ASSERT_OK_ZERO(sd_bus_error_set_errnof(&error, /* error= */ 0, "Waldi %c", 'X'));
        ASSERT_NULL(error.name);
        ASSERT_NULL(error.message);
        ASSERT_FALSE(sd_bus_error_has_name(&error, SD_BUS_ERROR_IO_ERROR));
        ASSERT_EQ(sd_bus_error_get_errno(&error), 0);
        ASSERT_FALSE(sd_bus_error_is_set(&error));
}

extern const sd_bus_error_map __start_SYSTEMD_BUS_ERROR_MAP[];
extern const sd_bus_error_map __stop_SYSTEMD_BUS_ERROR_MAP[];

static int dump_mapping_table(void) {
        printf("----- errno mappings ------\n");
        for (const sd_bus_error_map *m = __start_SYSTEMD_BUS_ERROR_MAP; m < __stop_SYSTEMD_BUS_ERROR_MAP; m++) {
                assert((uintptr_t) m % sizeof(void*) == 0);

                if (m->code != BUS_ERROR_MAP_END_MARKER)
                        printf("%s -> %i/%s\n", strna(m->name), m->code, ERRNO_NAME(m->code));
        }
        printf("---------------------------\n");

        return EXIT_SUCCESS;
}

TEST(errno_mapping_standard) {
        ASSERT_ERROR(sd_bus_error_set(NULL, "System.Error.EUCLEAN", /* message= */ NULL), EUCLEAN);
        ASSERT_ERROR(sd_bus_error_set(NULL, "System.Error.EBUSY", /* message= */ NULL), EBUSY);
        ASSERT_ERROR(sd_bus_error_set(NULL, "System.Error.EINVAL", /* message= */ NULL), EINVAL);
        ASSERT_ERROR(sd_bus_error_set(NULL, "System.Error.WHATSIT", /* message= */ NULL), EIO);
}

BUS_ERROR_MAP_ELF_REGISTER static const sd_bus_error_map test_errors[] = {
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error", 5),
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-2", 52),
        SD_BUS_ERROR_MAP_END
};

BUS_ERROR_MAP_ELF_REGISTER static const sd_bus_error_map test_errors2[] = {
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-3", 33),
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-4", 44),
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-33", 333),
        SD_BUS_ERROR_MAP_END
};

static const sd_bus_error_map test_errors3[] = {
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-88", 888),
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-99", 999),
        SD_BUS_ERROR_MAP_END
};

static const sd_bus_error_map test_errors4[] = {
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-77", 777),
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-78", 778),
        SD_BUS_ERROR_MAP_END
};

static const sd_bus_error_map test_errors_bad1[] = {
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-1", 0),
        SD_BUS_ERROR_MAP_END
};

static const sd_bus_error_map test_errors_bad2[] = {
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-1", -1),
        SD_BUS_ERROR_MAP_END
};

TEST(errno_mapping_custom) {
        ASSERT_EQ(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error", /* message= */ NULL), -5);
        ASSERT_EQ(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-2", /* message= */ NULL), -52);
        ASSERT_ERROR(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-x", /* message= */ NULL), EIO);
        ASSERT_EQ(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-33", /* message= */ NULL), -333);

        ASSERT_ERROR(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-88", /* message= */ NULL), EIO);
        ASSERT_ERROR(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-99", /* message= */ NULL), EIO);
        ASSERT_ERROR(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-77", /* message= */ NULL), EIO);

        ASSERT_OK_POSITIVE(sd_bus_error_add_map(test_errors3));
        ASSERT_EQ(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-88", /* message= */ NULL), -888);
        ASSERT_OK_POSITIVE(sd_bus_error_add_map(test_errors4));
        ASSERT_OK_EQ(sd_bus_error_add_map(test_errors4), 0);
        ASSERT_OK_EQ(sd_bus_error_add_map(test_errors3), 0);

        ASSERT_EQ(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-99", /* message= */ NULL), -999);
        ASSERT_EQ(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-77", /* message= */ NULL), -777);
        ASSERT_EQ(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-78", /* message= */ NULL), -778);
        ASSERT_EQ(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-2", /* message= */ NULL), -52);
        ASSERT_ERROR(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-y", /* message= */ NULL), EIO);

        ASSERT_ERROR(sd_bus_error_set(NULL, BUS_ERROR_NO_SUCH_UNIT, /* message= */ NULL), ENOENT);

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_bus_error_add_map(test_errors_bad1), EINVAL));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_bus_error_add_map(test_errors_bad2), EINVAL));
}

TEST(sd_bus_error_set_errnof) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *str = NULL;

        ASSERT_OK_ZERO(sd_bus_error_set_errnof(NULL, /* error= */ 0, /* format= */ NULL));
        ASSERT_ERROR(sd_bus_error_set_errnof(NULL, ENOANO, /* format= */ NULL), ENOANO);

        ASSERT_OK_ZERO(sd_bus_error_set_errnof(&error, /* error= */ 0, /* format= */ NULL));
        ASSERT_FALSE(bus_error_is_dirty(&error));

        ASSERT_ERROR(sd_bus_error_set_errnof(&error, EACCES, /* format= */ NULL), EACCES);
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_ACCESS_DENIED));
        ASSERT_STREQ(error.message, STRERROR(EACCES));

        str = mfree(str);
        sd_bus_error_free(&error);

        ASSERT_ERROR(sd_bus_error_set_errnof(&error, ENOANO, /* format= */ NULL), ENOANO);
        ASSERT_TRUE(sd_bus_error_has_name(&error, "System.Error.ENOANO"));
        ASSERT_STREQ(error.message, STRERROR(ENOANO));

        str = mfree(str);
        sd_bus_error_free(&error);

        ASSERT_EQ(sd_bus_error_set_errnof(&error, 100000, /* format= */ NULL), -100000);
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_FAILED));
        ASSERT_STREQ(error.message, STRERROR(100000));

        str = mfree(str);
        sd_bus_error_free(&error);

        ASSERT_OK_ZERO(sd_bus_error_set_errnof(NULL, /* error= */ 0, "hoge %s: %m", "foo"));
        ASSERT_ERROR(sd_bus_error_set_errnof(NULL, ENOANO, "hoge %s: %m", "foo"), ENOANO);

        ASSERT_OK_ZERO(sd_bus_error_set_errnof(&error, /* error= */ 0, "hoge %s: %m", "foo"));
        ASSERT_FALSE(bus_error_is_dirty(&error));

        ASSERT_ERROR(sd_bus_error_set_errnof(&error, EACCES, "hoge %s: %m", "foo"), EACCES);
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_ACCESS_DENIED));
        errno = EACCES;
        ASSERT_OK_ERRNO(asprintf(&str, "hoge %s: %m", "foo"));
        ASSERT_STREQ(error.message, str);

        str = mfree(str);
        sd_bus_error_free(&error);

        ASSERT_ERROR(sd_bus_error_set_errnof(&error, ENOANO, "hoge %s: %m", "foo"), ENOANO);
        ASSERT_TRUE(sd_bus_error_has_name(&error, "System.Error.ENOANO"));
        errno = ENOANO;
        ASSERT_OK_ERRNO(asprintf(&str, "hoge %s: %m", "foo"));
        ASSERT_STREQ(error.message, str);

        str = mfree(str);
        sd_bus_error_free(&error);

        ASSERT_EQ(sd_bus_error_set_errnof(&error, 100000, "hoge %s: %m", "foo"), -100000);
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_FAILED));
        errno = 100000;
        ASSERT_OK_ERRNO(asprintf(&str, "hoge %s: %m", "foo"));
        ASSERT_STREQ(error.message, str);
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, dump_mapping_table);
