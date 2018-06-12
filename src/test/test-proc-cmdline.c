/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "log.h"
#include "macro.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "util.h"

static int obj;

static int parse_item(const char *key, const char *value, void *data) {
        assert_se(key);
        assert_se(data == &obj);

        log_info("kernel cmdline option <%s> = <%s>", key, strna(value));
        return 0;
}

static void test_proc_cmdline_parse(void) {
        assert_se(proc_cmdline_parse(parse_item, &obj, true) >= 0);
}

static void test_runlevel_to_target(void) {
        in_initrd_force(false);
        assert_se(streq_ptr(runlevel_to_target(NULL), NULL));
        assert_se(streq_ptr(runlevel_to_target("unknown-runlevel"), NULL));
        assert_se(streq_ptr(runlevel_to_target("rd.unknown-runlevel"), NULL));
        assert_se(streq_ptr(runlevel_to_target("3"), SPECIAL_MULTI_USER_TARGET));
        assert_se(streq_ptr(runlevel_to_target("rd.rescue"), NULL));

        in_initrd_force(true);
        assert_se(streq_ptr(runlevel_to_target(NULL), NULL));
        assert_se(streq_ptr(runlevel_to_target("unknown-runlevel"), NULL));
        assert_se(streq_ptr(runlevel_to_target("rd.unknown-runlevel"), NULL));
        assert_se(streq_ptr(runlevel_to_target("3"), NULL));
        assert_se(streq_ptr(runlevel_to_target("rd.rescue"), SPECIAL_RESCUE_TARGET));
}

static void test_proc_cmdline_get_key(void) {
        _cleanup_free_ char *value = NULL;

        putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar=quux wuff-piep=tuet zumm");

        assert_se(proc_cmdline_get_key("", 0, &value) == -EINVAL);
        assert_se(proc_cmdline_get_key("abc", 0, NULL) == 0);
        assert_se(proc_cmdline_get_key("abc", 0, &value) == 0 && value == NULL);
        assert_se(proc_cmdline_get_key("abc", PROC_CMDLINE_VALUE_OPTIONAL, &value) == 0 && value == NULL);

        assert_se(proc_cmdline_get_key("foo_bar", 0, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("foo_bar", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("foo-bar", 0, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("foo-bar", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("foo-bar", 0, NULL) == 0);
        assert_se(proc_cmdline_get_key("foo-bar", PROC_CMDLINE_VALUE_OPTIONAL, NULL) == -EINVAL);

        assert_se(proc_cmdline_get_key("wuff-piep", 0, &value) > 0 && streq_ptr(value, "tuet"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("wuff-piep", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && streq_ptr(value, "tuet"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("wuff_piep", 0, &value) > 0 && streq_ptr(value, "tuet"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("wuff_piep", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && streq_ptr(value, "tuet"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("wuff_piep", 0, NULL) == 0);
        assert_se(proc_cmdline_get_key("wuff_piep", PROC_CMDLINE_VALUE_OPTIONAL, NULL) == -EINVAL);

        assert_se(proc_cmdline_get_key("zumm", 0, &value) == 0 && value == NULL);
        assert_se(proc_cmdline_get_key("zumm", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && value == NULL);
        assert_se(proc_cmdline_get_key("zumm", 0, NULL) > 0);
}

static void test_proc_cmdline_get_bool(void) {
        bool value = false;

        putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar bar-waldo=1 x_y-z=0 quux=miep");

        assert_se(proc_cmdline_get_bool("", &value) == -EINVAL);
        assert_se(proc_cmdline_get_bool("abc", &value) == 0 && value == false);
        assert_se(proc_cmdline_get_bool("foo_bar", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("foo-bar", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("bar-waldo", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("bar_waldo", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("x_y-z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("x-y-z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("x-y_z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("x_y_z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("quux", &value) == -EINVAL && value == false);
}

static void test_proc_cmdline_key_streq(void) {

        assert_se(proc_cmdline_key_streq("", ""));
        assert_se(proc_cmdline_key_streq("a", "a"));
        assert_se(!proc_cmdline_key_streq("", "a"));
        assert_se(!proc_cmdline_key_streq("a", ""));
        assert_se(proc_cmdline_key_streq("a", "a"));
        assert_se(!proc_cmdline_key_streq("a", "b"));
        assert_se(proc_cmdline_key_streq("x-y-z", "x-y-z"));
        assert_se(proc_cmdline_key_streq("x-y-z", "x_y_z"));
        assert_se(proc_cmdline_key_streq("x-y-z", "x-y_z"));
        assert_se(proc_cmdline_key_streq("x-y-z", "x_y-z"));
        assert_se(proc_cmdline_key_streq("x_y-z", "x-y_z"));
        assert_se(!proc_cmdline_key_streq("x_y-z", "x-z_z"));
}

static void test_proc_cmdline_key_startswith(void) {

        assert_se(proc_cmdline_key_startswith("", ""));
        assert_se(proc_cmdline_key_startswith("x", ""));
        assert_se(!proc_cmdline_key_startswith("", "x"));
        assert_se(proc_cmdline_key_startswith("x", "x"));
        assert_se(!proc_cmdline_key_startswith("x", "y"));
        assert_se(!proc_cmdline_key_startswith("foo-bar", "quux"));
        assert_se(proc_cmdline_key_startswith("foo-bar", "foo"));
        assert_se(proc_cmdline_key_startswith("foo-bar", "foo-bar"));
        assert_se(proc_cmdline_key_startswith("foo-bar", "foo_bar"));
        assert_se(proc_cmdline_key_startswith("foo-bar", "foo_"));
        assert_se(!proc_cmdline_key_startswith("foo-bar", "foo_xx"));
}

int main(void) {
        log_parse_environment();
        log_open();

        test_proc_cmdline_parse();
        test_proc_cmdline_key_streq();
        test_proc_cmdline_key_startswith();
        test_proc_cmdline_get_key();
        test_proc_cmdline_get_bool();
        test_runlevel_to_target();

        return 0;
}
