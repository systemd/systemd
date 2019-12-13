/* SPDX-License-Identifier: LGPL-2.1+ */

#include "env-file.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

#define env_file_1                              \
        "a=a\n"                                 \
        "b=b\\\n"                               \
        "c\n"                                   \
        "d=d\\\n"                               \
        "e\\\n"                                 \
        "f\n"                                   \
        "g=g\\ \n"                              \
        "h=h\n"                                 \
        "i=i\\"

#define env_file_2                              \
        "a=a\\\n"

#define env_file_3 \
        "#SPAMD_ARGS=\"-d --socketpath=/var/lib/bulwark/spamd \\\n" \
        "#--nouser-config                                     \\\n" \
        "normal=line"

#define env_file_4 \
       "# Generated\n" \
       "\n" \
       "HWMON_MODULES=\"coretemp f71882fg\"\n" \
       "\n" \
       "# For compatibility reasons\n" \
       "\n" \
       "MODULE_0=coretemp\n" \
       "MODULE_1=f71882fg"

#define env_file_5                              \
        "a=\n"                                 \
        "b="

static void test_load_env_file_1(void) {
        _cleanup_strv_free_ char **data = NULL;
        int r;

        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_1, strlen(env_file_1)) == strlen(env_file_1));

        r = load_env_file(NULL, name, &data);
        assert_se(r == 0);
        assert_se(streq(data[0], "a=a"));
        assert_se(streq(data[1], "b=bc"));
        assert_se(streq(data[2], "d=def"));
        assert_se(streq(data[3], "g=g "));
        assert_se(streq(data[4], "h=h"));
        assert_se(streq(data[5], "i=i"));
        assert_se(data[6] == NULL);
}

static void test_load_env_file_2(void) {
        _cleanup_strv_free_ char **data = NULL;
        int r;

        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_2, strlen(env_file_2)) == strlen(env_file_2));

        r = load_env_file(NULL, name, &data);
        assert_se(r == 0);
        assert_se(streq(data[0], "a=a"));
        assert_se(data[1] == NULL);
}

static void test_load_env_file_3(void) {
        _cleanup_strv_free_ char **data = NULL;
        int r;

        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_3, strlen(env_file_3)) == strlen(env_file_3));

        r = load_env_file(NULL, name, &data);
        assert_se(r == 0);
        assert_se(data == NULL);
}

static void test_load_env_file_4(void) {
        _cleanup_strv_free_ char **data = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;
        int r;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_4, strlen(env_file_4)) == strlen(env_file_4));

        r = load_env_file(NULL, name, &data);
        assert_se(r == 0);
        assert_se(streq(data[0], "HWMON_MODULES=coretemp f71882fg"));
        assert_se(streq(data[1], "MODULE_0=coretemp"));
        assert_se(streq(data[2], "MODULE_1=f71882fg"));
        assert_se(data[3] == NULL);
}

static void test_load_env_file_5(void) {
        _cleanup_strv_free_ char **data = NULL;
        int r;

        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_5, strlen(env_file_5)) == strlen(env_file_5));

        r = load_env_file(NULL, name, &data);
        assert_se(r == 0);
        assert_se(streq(data[0], "a="));
        assert_se(streq(data[1], "b="));
        assert_se(data[2] == NULL);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        test_load_env_file_1();
        test_load_env_file_2();
        test_load_env_file_3();
        test_load_env_file_4();
        test_load_env_file_5();
}
