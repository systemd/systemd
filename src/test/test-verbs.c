/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strv.h"
#include "tests.h"
#include "verbs.h"

static int noop_dispatcher(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return 0;
}

#define test_dispatch_one(argv, verbs, expected) \
        assert_se(_dispatch_verb(argv, verbs, verbs + ELEMENTSOF(verbs) - 1, NULL) == expected);

TEST(verbs) {
        static const Verb verbs[] = {
                { "help",        VERB_ANY, VERB_ANY, 0,                 noop_dispatcher },
                { "list-images", VERB_ANY, 1,        0,                 noop_dispatcher },
                { "list",        VERB_ANY, 2,        VERB_DEFAULT,      noop_dispatcher },
                { "status",      2,        VERB_ANY, 0,                 noop_dispatcher },
                { "Group2",      VERB_ANY, VERB_ANY, VERB_GROUP_MARKER, NULL            },
                { "show",        VERB_ANY, VERB_ANY, 0,                 noop_dispatcher },
                { "terminate",   2,        VERB_ANY, 0,                 noop_dispatcher },
                { "Group3",      0,        0,        VERB_GROUP_MARKER, NULL            },
                { "login",       2,        2,        0,                 noop_dispatcher },
                { "copy-to",     3,        4,        0,                 noop_dispatcher },
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
        test_dispatch_one(STRV_EMPTY, verbs, 0);

        /* the group entry shall not be found */
        test_dispatch_one(STRV_MAKE("Group2"), verbs, -EINVAL);

        /* the group entry shall not be found */
        test_dispatch_one(STRV_MAKE("Group3"), verbs, -EINVAL);
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
                { "help",        VERB_ANY, VERB_ANY, 0,                 noop_dispatcher },
                { "list-images", VERB_ANY, 1,        0,                 noop_dispatcher },
                { "list",        VERB_ANY, 2,        0,                 noop_dispatcher },
                { "status",      2,        VERB_ANY, 0,                 noop_dispatcher },
                { "Specials",    VERB_ANY, VERB_ANY, VERB_GROUP_MARKER, NULL            },
                { "show",        VERB_ANY, VERB_ANY, 0,                 noop_dispatcher },
                { "terminate",   2,        VERB_ANY, 0,                 noop_dispatcher },
                { "login",       2,        2,        0,                 noop_dispatcher },
                { "copy-to",     3,        4,        0,                 noop_dispatcher },
                {}
        };

        test_dispatch_one(STRV_MAKE(NULL), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hel"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("helpp"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hgrejgoraoiosafso"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("Specials"), verbs, -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
