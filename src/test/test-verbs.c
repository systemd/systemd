/***
  This file is part of systemd.

  Copyright 2014 systemd developers

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

#include "macro.h"
#include "strv.h"
#include "verbs.h"

static int noop_dispatcher(int argc, char *argv[], void *userdata) {
        return 0;
}

#define test_dispatch_one(argv, verbs, expected) \
        optind = 0; \
        assert_se(dispatch_verb(strv_length(argv), argv, verbs, NULL) == expected);

static void test_verbs(void) {
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

static void test_verbs_no_default(void) {
        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, noop_dispatcher },
                {},
        };

        test_dispatch_one(STRV_MAKE(NULL), verbs, -EINVAL);
}

int main(int argc, char *argv[]) {
        test_verbs();
        test_verbs_no_default();

        return 0;
}
