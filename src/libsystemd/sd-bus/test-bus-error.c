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

        assert_se(!sd_bus_error_is_set(&error));
        assert_se(sd_bus_error_set(&error, SD_BUS_ERROR_NOT_SUPPORTED, "xxx") == -EOPNOTSUPP);
        assert_se(streq(error.name, SD_BUS_ERROR_NOT_SUPPORTED));
        assert_se(streq(error.message, "xxx"));
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_NOT_SUPPORTED));
        assert_se(sd_bus_error_has_names_sentinel(&error, SD_BUS_ERROR_NOT_SUPPORTED, NULL));
        assert_se(sd_bus_error_has_names(&error, SD_BUS_ERROR_NOT_SUPPORTED));
        assert_se(sd_bus_error_has_names(&error, SD_BUS_ERROR_NOT_SUPPORTED, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(sd_bus_error_has_names(&error, SD_BUS_ERROR_FILE_NOT_FOUND, SD_BUS_ERROR_NOT_SUPPORTED, NULL));
        assert_se(!sd_bus_error_has_names(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(sd_bus_error_get_errno(&error) == EOPNOTSUPP);
        assert_se(sd_bus_error_is_set(&error));
        sd_bus_error_free(&error);

        /* Check with no error */
        assert_se(!sd_bus_error_is_set(&error));
        assert_se(sd_bus_error_setf(&error, NULL, "yyy %i", -1) == 0);
        assert_se(error.name == NULL);
        assert_se(error.message == NULL);
        assert_se(!sd_bus_error_has_name(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(!sd_bus_error_has_names(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(sd_bus_error_get_errno(&error) == 0);
        assert_se(!sd_bus_error_is_set(&error));

        assert_se(sd_bus_error_setf(&error, SD_BUS_ERROR_FILE_NOT_FOUND, "yyy %i", -1) == -ENOENT);
        assert_se(streq(error.name, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(streq(error.message, "yyy -1"));
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(sd_bus_error_has_names(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(sd_bus_error_get_errno(&error) == ENOENT);
        assert_se(sd_bus_error_is_set(&error));

        assert_se(!sd_bus_error_is_set(&second));
        assert_se(second._need_free == 0);
        assert_se(error._need_free > 0);
        assert_se(sd_bus_error_copy(&second, &error) == -ENOENT);
        assert_se(second._need_free > 0);
        assert_se(streq(error.name, second.name));
        assert_se(streq(error.message, second.message));
        assert_se(sd_bus_error_get_errno(&second) == ENOENT);
        assert_se(sd_bus_error_has_name(&second, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(sd_bus_error_has_names(&second, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(sd_bus_error_is_set(&second));

        sd_bus_error_free(&error);
        sd_bus_error_free(&second);

        assert_se(!sd_bus_error_is_set(&second));
        assert_se(const_error._need_free == 0);
        assert_se(sd_bus_error_copy(&second, &const_error) == -EEXIST);
        assert_se(second._need_free == 0);
        assert_se(streq(const_error.name, second.name));
        assert_se(streq(const_error.message, second.message));
        assert_se(sd_bus_error_get_errno(&second) == EEXIST);
        assert_se(sd_bus_error_has_name(&second, SD_BUS_ERROR_FILE_EXISTS));
        assert_se(sd_bus_error_is_set(&second));
        sd_bus_error_free(&second);

        assert_se(!sd_bus_error_is_set(&second));
        assert_se(temporarily_const_error._need_free < 0);
        assert_se(sd_bus_error_copy(&second, &temporarily_const_error) == -EACCES);
        assert_se(second._need_free > 0);
        assert_se(streq(temporarily_const_error.name, second.name));
        assert_se(streq(temporarily_const_error.message, second.message));
        assert_se(sd_bus_error_get_errno(&second) == EACCES);
        assert_se(sd_bus_error_has_name(&second, SD_BUS_ERROR_ACCESS_DENIED));
        assert_se(sd_bus_error_is_set(&second));

        assert_se(!sd_bus_error_is_set(&error));
        assert_se(sd_bus_error_set_const(&error, "System.Error.EUCLEAN", "Hallo") == -EUCLEAN);
        assert_se(streq(error.name, "System.Error.EUCLEAN"));
        assert_se(streq(error.message, "Hallo"));
        assert_se(sd_bus_error_has_name(&error, "System.Error.EUCLEAN"));
        assert_se(sd_bus_error_get_errno(&error) == EUCLEAN);
        assert_se(sd_bus_error_is_set(&error));
        sd_bus_error_free(&error);

        assert_se(!sd_bus_error_is_set(&error));
        assert_se(sd_bus_error_set_errno(&error, EBUSY) == -EBUSY);
        assert_se(streq(error.name, "System.Error.EBUSY"));
        assert_se(streq(error.message, STRERROR(EBUSY)));
        assert_se(sd_bus_error_has_name(&error, "System.Error.EBUSY"));
        assert_se(sd_bus_error_get_errno(&error) == EBUSY);
        assert_se(sd_bus_error_is_set(&error));
        sd_bus_error_free(&error);

        assert_se(!sd_bus_error_is_set(&error));
        assert_se(sd_bus_error_set_errnof(&error, EIO, "Waldi %c", 'X') == -EIO);
        assert_se(streq(error.name, SD_BUS_ERROR_IO_ERROR));
        assert_se(streq(error.message, "Waldi X"));
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_IO_ERROR));
        assert_se(sd_bus_error_get_errno(&error) == EIO);
        assert_se(sd_bus_error_is_set(&error));
        sd_bus_error_free(&error);

        /* Check with no error */
        assert_se(!sd_bus_error_is_set(&error));
        assert_se(sd_bus_error_set_errnof(&error, 0, "Waldi %c", 'X') == 0);
        assert_se(error.name == NULL);
        assert_se(error.message == NULL);
        assert_se(!sd_bus_error_has_name(&error, SD_BUS_ERROR_IO_ERROR));
        assert_se(sd_bus_error_get_errno(&error) == 0);
        assert_se(!sd_bus_error_is_set(&error));
}

extern const sd_bus_error_map __start_SYSTEMD_BUS_ERROR_MAP[];
extern const sd_bus_error_map __stop_SYSTEMD_BUS_ERROR_MAP[];

static int dump_mapping_table(void) {
        const sd_bus_error_map *m;

        printf("----- errno mappings ------\n");
        m = ALIGN_PTR(__start_SYSTEMD_BUS_ERROR_MAP);
        while (m < __stop_SYSTEMD_BUS_ERROR_MAP) {

                if (m->code == BUS_ERROR_MAP_END_MARKER) {
                        m = ALIGN_PTR(m + 1);
                        continue;
                }

                printf("%s -> %i/%s\n", strna(m->name), m->code, strna(errno_to_name(m->code)));
                m++;
        }
        printf("---------------------------\n");

        return EXIT_SUCCESS;
}

TEST(errno_mapping_standard) {
        assert_se(sd_bus_error_set(NULL, "System.Error.EUCLEAN", NULL) == -EUCLEAN);
        assert_se(sd_bus_error_set(NULL, "System.Error.EBUSY", NULL) == -EBUSY);
        assert_se(sd_bus_error_set(NULL, "System.Error.EINVAL", NULL) == -EINVAL);
        assert_se(sd_bus_error_set(NULL, "System.Error.WHATSIT", NULL) == -EIO);
}

BUS_ERROR_MAP_ELF_REGISTER const sd_bus_error_map test_errors[] = {
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error", 5),
        SD_BUS_ERROR_MAP("org.freedesktop.custom-dbus-error-2", 52),
        SD_BUS_ERROR_MAP_END
};

BUS_ERROR_MAP_ELF_REGISTER const sd_bus_error_map test_errors2[] = {
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
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error", NULL) == -5);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-2", NULL) == -52);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-x", NULL) == -EIO);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-33", NULL) == -333);

        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-88", NULL) == -EIO);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-99", NULL) == -EIO);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-77", NULL) == -EIO);

        assert_se(sd_bus_error_add_map(test_errors3) > 0);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-88", NULL) == -888);
        assert_se(sd_bus_error_add_map(test_errors4) > 0);
        assert_se(sd_bus_error_add_map(test_errors4) == 0);
        assert_se(sd_bus_error_add_map(test_errors3) == 0);

        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-99", NULL) == -999);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-77", NULL) == -777);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-78", NULL) == -778);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-2", NULL) == -52);
        assert_se(sd_bus_error_set(NULL, "org.freedesktop.custom-dbus-error-y", NULL) == -EIO);

        assert_se(sd_bus_error_set(NULL, BUS_ERROR_NO_SUCH_UNIT, NULL) == -ENOENT);

        ASSERT_RETURN_EXPECTED_SE(sd_bus_error_add_map(test_errors_bad1) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_bus_error_add_map(test_errors_bad2) == -EINVAL);
}

TEST(sd_bus_error_set_errnof) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *str = NULL;

        assert_se(sd_bus_error_set_errnof(NULL, 0, NULL) == 0);
        assert_se(sd_bus_error_set_errnof(NULL, ENOANO, NULL) == -ENOANO);

        assert_se(sd_bus_error_set_errnof(&error, 0, NULL) == 0);
        assert_se(!bus_error_is_dirty(&error));

        assert_se(sd_bus_error_set_errnof(&error, EACCES, NULL) == -EACCES);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_ACCESS_DENIED));
        errno = EACCES;
        assert_se(asprintf(&str, "%m") >= 0);
        assert_se(streq(error.message, str));
        assert_se(error._need_free == 0);

        str = mfree(str);
        sd_bus_error_free(&error);

        assert_se(sd_bus_error_set_errnof(&error, ENOANO, NULL) == -ENOANO);
        assert_se(sd_bus_error_has_name(&error, "System.Error.ENOANO"));
        errno = ENOANO;
        assert_se(asprintf(&str, "%m") >= 0);
        assert_se(streq(error.message, str));
        assert_se(error._need_free == 1);

        str = mfree(str);
        sd_bus_error_free(&error);

        assert_se(sd_bus_error_set_errnof(&error, 100000, NULL) == -100000);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_FAILED));
        errno = 100000;
        assert_se(asprintf(&str, "%m") >= 0);
        assert_se(streq(error.message, str));
        assert_se(error._need_free == 1);

        str = mfree(str);
        sd_bus_error_free(&error);

        assert_se(sd_bus_error_set_errnof(NULL, 0, "hoge %s: %m", "foo") == 0);
        assert_se(sd_bus_error_set_errnof(NULL, ENOANO, "hoge %s: %m", "foo") == -ENOANO);

        assert_se(sd_bus_error_set_errnof(&error, 0, "hoge %s: %m", "foo") == 0);
        assert_se(!bus_error_is_dirty(&error));

        assert_se(sd_bus_error_set_errnof(&error, EACCES, "hoge %s: %m", "foo") == -EACCES);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_ACCESS_DENIED));
        errno = EACCES;
        assert_se(asprintf(&str, "hoge %s: %m", "foo") >= 0);
        assert_se(streq(error.message, str));
        assert_se(error._need_free == 1);

        str = mfree(str);
        sd_bus_error_free(&error);

        assert_se(sd_bus_error_set_errnof(&error, ENOANO, "hoge %s: %m", "foo") == -ENOANO);
        assert_se(sd_bus_error_has_name(&error, "System.Error.ENOANO"));
        errno = ENOANO;
        assert_se(asprintf(&str, "hoge %s: %m", "foo") >= 0);
        assert_se(streq(error.message, str));
        assert_se(error._need_free == 1);

        str = mfree(str);
        sd_bus_error_free(&error);

        assert_se(sd_bus_error_set_errnof(&error, 100000, "hoge %s: %m", "foo") == -100000);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_FAILED));
        errno = 100000;
        assert_se(asprintf(&str, "hoge %s: %m", "foo") >= 0);
        assert_se(streq(error.message, str));
        assert_se(error._need_free == 1);
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, dump_mapping_table);
