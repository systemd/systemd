/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "macro.h"
#include "strv.h"
#include "tests.h"
#include "verbs.h"

static int noop_dispatcher(int argc, char *argv[], void *userdata) {
        return 0;
}

#define test_dispatch_one(argv, verbs, expected) \
        optind = 0; \
        assert_se(dispatch_verb(strv_length(argv), argv, verbs, NULL) == expected);

TEST(verbs) {
        static const Verb verbs[] = {
                { "help",        VERB_ANY, VERB_ANY, 0,            noop_dispatcher },
                { "list-images", VERB_ANY, 1,        0,            noop_dispatcher },
                { "list",        VERB_ANY, 2,        VERB_DEFAULT, noop_dispatcher },
                { "status",      2,        VERB_ANY, 0,            noop_dispatcher },
                { "show",        VERB_ANY, VERB_ANY, 0,            noop_dispatcher },
                { "terminate",   2,        VERB_ANY, 0,            noop_dispatcher },
                { "login",       2,        2,        0,            noop_dispatcher },
                { "copy-to",     3,        4,        0,            noop_dispatcher },
                {}
        };

        /* not found */
        test_dispatch_one(STRV_MAKE("command-not-found"), verbs, -EINVAL);

        /* found */
        test_dispatch_one(STRV_MAKE("show"), verbs, 0);

        /* found, too few args */
        test_dispatch_one(STRV_MAKE("copy-to", "foo"), verbs, -EINVAL);

        /* found, meets min args */
        test_dispatch_one(STRV_MAKE("status", "foo", "bar"), verbs, 0);

        /* found, too many args */
        test_dispatch_one(STRV_MAKE("copy-to", "foo", "bar", "baz", "quux", "qaax"), verbs, -EINVAL);

        /* no verb, but a default is set */
        test_dispatch_one(STRV_MAKE_EMPTY, verbs, 0);
}

TEST(verbs_no_default) {
        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, noop_dispatcher },
                {},
        };

        test_dispatch_one(STRV_MAKE(NULL), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hel"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("helpp"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hgrejgoraoiosafso"), verbs, -EINVAL);
}

TEST(verbs_no_default_many) {
        static const Verb verbs[] = {
                { "help",        VERB_ANY, VERB_ANY, 0,            noop_dispatcher },
                { "list-images", VERB_ANY, 1,        0,            noop_dispatcher },
                { "list",        VERB_ANY, 2,        0,            noop_dispatcher },
                { "status",      2,        VERB_ANY, 0,            noop_dispatcher },
                { "show",        VERB_ANY, VERB_ANY, 0,            noop_dispatcher },
                { "terminate",   2,        VERB_ANY, 0,            noop_dispatcher },
                { "login",       2,        2,        0,            noop_dispatcher },
                { "copy-to",     3,        4,        0,            noop_dispatcher },
                {}
        };

        test_dispatch_one(STRV_MAKE(NULL), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hel"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("helpp"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hgrejgoraoiosafso"), verbs, -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
