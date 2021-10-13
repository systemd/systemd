/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "hostname-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_hostname_is_valid(void) {
        log_info("/* %s */", __func__);

        assert_se(hostname_is_valid("foobar", 0));
        assert_se(hostname_is_valid("foobar.com", 0));
        assert_se(!hostname_is_valid("foobar.com.", 0));
        assert_se(hostname_is_valid("fooBAR", 0));
        assert_se(hostname_is_valid("fooBAR.com", 0));
        assert_se(!hostname_is_valid("fooBAR.", 0));
        assert_se(!hostname_is_valid("fooBAR.com.", 0));
        assert_se(!hostname_is_valid("fööbar", 0));
        assert_se(!hostname_is_valid("", 0));
        assert_se(!hostname_is_valid(".", 0));
        assert_se(!hostname_is_valid("..", 0));
        assert_se(!hostname_is_valid("foobar.", 0));
        assert_se(!hostname_is_valid(".foobar", 0));
        assert_se(!hostname_is_valid("foo..bar", 0));
        assert_se(!hostname_is_valid("foo.bar..", 0));
        assert_se(!hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0));
        assert_se(!hostname_is_valid("au-xph5-rvgrdsb5hcxc-47et3a5vvkrc-server-wyoz4elpdpe3.openstack.local", 0));

        assert_se(hostname_is_valid("foobar", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("foobar.com", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("foobar.com.", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("fooBAR", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("fooBAR.com", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("fooBAR.", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("fooBAR.com.", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("fööbar", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid(".", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("..", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("foobar.", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid(".foobar", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("foo..bar", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("foo.bar..", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", VALID_HOSTNAME_TRAILING_DOT));
}

static void test_hostname_cleanup(void) {
        char *s;

        log_info("/* %s */", __func__);

        s = strdupa_safe("foobar");
        assert_se(streq(hostname_cleanup(s), "foobar"));
        s = strdupa_safe("foobar.com");
        assert_se(streq(hostname_cleanup(s), "foobar.com"));
        s = strdupa_safe("foobar.com.");
        assert_se(streq(hostname_cleanup(s), "foobar.com"));
        s = strdupa_safe("foo-bar.-com-.");
        assert_se(streq(hostname_cleanup(s), "foo-bar.com"));
        s = strdupa_safe("foo-bar-.-com-.");
        assert_se(streq(hostname_cleanup(s), "foo-bar--com"));
        s = strdupa_safe("--foo-bar.-com");
        assert_se(streq(hostname_cleanup(s), "foo-bar.com"));
        s = strdupa_safe("fooBAR");
        assert_se(streq(hostname_cleanup(s), "fooBAR"));
        s = strdupa_safe("fooBAR.com");
        assert_se(streq(hostname_cleanup(s), "fooBAR.com"));
        s = strdupa_safe("fooBAR.");
        assert_se(streq(hostname_cleanup(s), "fooBAR"));
        s = strdupa_safe("fooBAR.com.");
        assert_se(streq(hostname_cleanup(s), "fooBAR.com"));
        s = strdupa_safe("fööbar");
        assert_se(streq(hostname_cleanup(s), "fbar"));
        s = strdupa_safe("");
        assert_se(isempty(hostname_cleanup(s)));
        s = strdupa_safe(".");
        assert_se(isempty(hostname_cleanup(s)));
        s = strdupa_safe("..");
        assert_se(isempty(hostname_cleanup(s)));
        s = strdupa_safe("foobar.");
        assert_se(streq(hostname_cleanup(s), "foobar"));
        s = strdupa_safe(".foobar");
        assert_se(streq(hostname_cleanup(s), "foobar"));
        s = strdupa_safe("foo..bar");
        assert_se(streq(hostname_cleanup(s), "foo.bar"));
        s = strdupa_safe("foo.bar..");
        assert_se(streq(hostname_cleanup(s), "foo.bar"));
        s = strdupa_safe("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_se(streq(hostname_cleanup(s), "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        s = strdupa_safe("xxxx........xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_se(streq(hostname_cleanup(s), "xxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
}

static void test_hostname_malloc(void) {
        _cleanup_free_ char *h = NULL, *l = NULL;

        log_info("/* %s */", __func__);

        assert_se(h = gethostname_malloc());
        log_info("hostname_malloc: \"%s\"", h);

        assert_se(l = gethostname_short_malloc());
        log_info("hostname_short_malloc: \"%s\"", l);
}

static void test_default_hostname(void) {
        log_info("/* %s */", __func__);

        if (!hostname_is_valid(FALLBACK_HOSTNAME, 0)) {
                log_error("Configured fallback hostname \"%s\" is not valid.", FALLBACK_HOSTNAME);
                exit(EXIT_FAILURE);
        }

        _cleanup_free_ char *n = get_default_hostname();
        assert_se(n);
        log_info("get_default_hostname: \"%s\"", n);
        assert_se(hostname_is_valid(n, 0));
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_hostname_is_valid();
        test_hostname_cleanup();
        test_hostname_malloc();
        test_default_hostname();

        return 0;
}
