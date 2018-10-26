/* SPDX-License-Identifier: LGPL-2.1+ */

#include "def.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "serialize.h"
#include "strv.h"
#include "tests.h"

char long_string[LONG_LINE_MAX+1];

static void test_serialize_item(void) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_item(f, "a", NULL) == 0);
        assert_se(serialize_item(f, "a", "bbb") == 1);
        assert_se(serialize_item(f, "a", "bbb") == 1);
        assert_se(serialize_item(f, "a", long_string) == -EINVAL);
        assert_se(serialize_item(f, long_string, "a") == -EINVAL);
        assert_se(serialize_item(f, long_string, long_string) == -EINVAL);

        rewind(f);

        _cleanup_free_ char *line1 = NULL, *line2 = NULL, *line3 = NULL;
        assert_se(read_line(f, LONG_LINE_MAX, &line1) > 0);
        assert_se(streq(line1, "a=bbb"));
        assert_se(read_line(f, LONG_LINE_MAX, &line2) > 0);
        assert_se(streq(line2, "a=bbb"));
        assert_se(read_line(f, LONG_LINE_MAX, &line3) == 0);
        assert_se(streq(line3, ""));
}

static void test_serialize_item_escaped(void) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_item_escaped(f, "a", NULL) == 0);
        assert_se(serialize_item_escaped(f, "a", "bbb") == 1);
        assert_se(serialize_item_escaped(f, "a", "bbb") == 1);
        assert_se(serialize_item_escaped(f, "a", long_string) == -EINVAL);
        assert_se(serialize_item_escaped(f, long_string, "a") == -EINVAL);
        assert_se(serialize_item_escaped(f, long_string, long_string) == -EINVAL);

        rewind(f);

        _cleanup_free_ char *line1 = NULL, *line2 = NULL, *line3 = NULL;
        assert_se(read_line(f, LONG_LINE_MAX, &line1) > 0);
        assert_se(streq(line1, "a=bbb"));
        assert_se(read_line(f, LONG_LINE_MAX, &line2) > 0);
        assert_se(streq(line2, "a=bbb"));
        assert_se(read_line(f, LONG_LINE_MAX, &line3) == 0);
        assert_se(streq(line3, ""));
}

static void test_serialize_usec(void) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_usec(f, "usec1", USEC_INFINITY) == 0);
        assert_se(serialize_usec(f, "usec2", 0) == 1);
        assert_se(serialize_usec(f, "usec3", USEC_INFINITY-1) == 1);

        rewind(f);

        _cleanup_free_ char *line1 = NULL, *line2 = NULL;
        usec_t x;

        assert_se(read_line(f, LONG_LINE_MAX, &line1) > 0);
        assert_se(streq(line1, "usec2=0"));
        assert_se(deserialize_usec(line1 + 6, &x) == 0);
        assert_se(x == 0);

        assert_se(read_line(f, LONG_LINE_MAX, &line2) > 0);
        assert_se(startswith(line2, "usec3="));
        assert_se(deserialize_usec(line2 + 6, &x) == 0);
        assert_se(x == USEC_INFINITY-1);
}

static void test_serialize_strv(void) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        char **strv = STRV_MAKE("a", "b", "foo foo",
                                "nasty1 \"",
                                "\"nasty2 ",
                                "nasty3 '",
                                "\"nasty4 \"",
                                "nasty5\n",
                                "\nnasty5\nfoo=bar",
                                "\nnasty5\nfoo=bar");

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_strv(f, "strv1", NULL) == 0);
        assert_se(serialize_strv(f, "strv2", STRV_MAKE_EMPTY) == 0);
        assert_se(serialize_strv(f, "strv3", strv) == 1);
        assert_se(serialize_strv(f, "strv4", STRV_MAKE(long_string)) == -EINVAL);

        rewind(f);

        _cleanup_strv_free_ char **strv2 = NULL;
        for (;;) {
                _cleanup_free_ char *line = NULL;
                int r;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r == 0)
                        break;
                assert_se(r > 0);

                const char *t = startswith(line, "strv3=");
                assert_se(t);

                char *un;
                assert_se(cunescape(t, 0, &un) >= 0);
                assert_se(strv_consume(&strv2, un) >= 0);
        }

        assert_se(strv_equal(strv, strv2));
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        memset(long_string, 'x', sizeof(long_string)-1);
        char_array_0(long_string);

        test_serialize_item();
        test_serialize_item_escaped();
        test_serialize_usec();
        test_serialize_strv();

        return EXIT_SUCCESS;
}
