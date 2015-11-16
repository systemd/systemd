/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-bus.h"

#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-util.h"
#include "errno-list.h"

static void test_error(void) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL, second = SD_BUS_ERROR_NULL;
        const sd_bus_error const_error = SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_FILE_EXISTS, "const error");
        const sd_bus_error temporarily_const_error = {
                .name = SD_BUS_ERROR_ACCESS_DENIED,
                .message = "oh! no",
                ._need_free = -1
        };

        assert_se(!sd_bus_error_is_set(&error));
        assert_se(sd_bus_error_set(&error, SD_BUS_ERROR_NOT_SUPPORTED, "xxx") == -EOPNOTSUPP);
        assert_se(streq(error.name, SD_BUS_ERROR_NOT_SUPPORTED));
        assert_se(streq(error.message, "xxx"));
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_NOT_SUPPORTED));
        assert_se(sd_bus_error_get_errno(&error) == EOPNOTSUPP);
        assert_se(sd_bus_error_is_set(&error));
        sd_bus_error_free(&error);

        assert_se(!sd_bus_error_is_set(&error));
        assert_se(sd_bus_error_setf(&error, SD_BUS_ERROR_FILE_NOT_FOUND, "yyy %i", -1) == -ENOENT);
        assert_se(streq(error.name, SD_BUS_ERROR_FILE_NOT_FOUND));
        assert_se(streq(error.message, "yyy -1"));
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_FILE_NOT_FOUND));
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
        assert_se(streq(error.message, strerror(EBUSY)));
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
}

extern const sd_bus_error_map __start_BUS_ERROR_MAP[];
extern const sd_bus_error_map __stop_BUS_ERROR_MAP[];

static void dump_mapping_table(void) {
        const sd_bus_error_map *m;

        printf("----- errno mappings ------\n");
        m = __start_BUS_ERROR_MAP;
        while (m < __stop_BUS_ERROR_MAP) {

                if (m->code == BUS_ERROR_MAP_END_MARKER) {
                        m = ALIGN8_PTR(m+1);
                        continue;
                }

                printf("%s -> %i/%s\n", strna(m->name), m->code, strna(errno_to_name(m->code)));
                m ++;
        }
        printf("---------------------------\n");
}

static void test_errno_mapping_standard(void) {
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

static void test_errno_mapping_custom(void) {
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
}

int main(int argc, char *argv[]) {
        dump_mapping_table();

        test_error();
        test_errno_mapping_standard();
        test_errno_mapping_custom();

        return 0;
}
