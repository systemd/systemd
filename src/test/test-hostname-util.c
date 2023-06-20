/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "hostname-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(hostname_is_valid) {
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

TEST(hostname_cleanup) {
        char *s;

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

TEST(hostname_malloc) {
        _cleanup_free_ char *h = NULL, *l = NULL;

        assert_se(h = gethostname_malloc());
        log_info("hostname_malloc: \"%s\"", h);

        assert_se(l = gethostname_short_malloc());
        log_info("hostname_short_malloc: \"%s\"", l);
}

TEST(default_hostname) {
        char *hostname;

        if (!hostname_is_valid(FALLBACK_HOSTNAME, 0)) {
                log_error("Configured fallback hostname \"%s\" is not valid.", FALLBACK_HOSTNAME);
                exit(EXIT_FAILURE);
        }

        /* SYSTEMD_DEFAULT_HOSTNAME environment variable takes precedence over everything else */
        assert_se(putenv((char*) "SYSTEMD_PROC_CMDLINE=hostname=foo") == 0);
        assert_se(putenv((char*) "SYSTEMD_DEFAULT_HOSTNAME=bar") == 0);
        hostname = get_default_hostname();
        assert_se(hostname);
        assert_se(streq(hostname, "bar"));
        hostname = mfree(hostname);

        /* Kernel commandline comes next */
        assert_se(putenv((char*) "SYSTEMD_DEFAULT_HOSTNAME=") == 0);
        hostname = get_default_hostname();
        assert_se(hostname);
        assert_se(streq(hostname, "foo"));
        hostname = mfree(hostname);

        /* Whatever comes next should at least be valid */
        assert_se(putenv((char*) "SYSTEMD_PROC_CMDLINE=") == 0);
        hostname = get_default_hostname();
        assert_se(hostname);
        log_info("get_default_hostname: \"%s\"", hostname);
        assert_se(hostname_is_valid(hostname, 0));
        hostname = mfree(hostname);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
