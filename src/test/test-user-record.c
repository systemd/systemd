/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "json-util.h"
#include "macro.h"
#include "tests.h"
#include "user-record.h"

#define USER(ret, ...)                          \
        ({                                      \
                typeof(ret) _r = (ret);         \
                user_record_unref(*_r);         \
                assert_se(user_record_build((ret), SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_STRING("disposition", "regular"), __VA_ARGS__)) >= 0); \
                0;                              \
        })

TEST(self_changes) {
        _cleanup_(user_record_unrefp) UserRecord *curr = NULL, *new = NULL;

        /* not allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 11111));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 99999));
        assert_se(!user_record_self_changes_allowed(curr, new));

        /* manually allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 11111),
             SD_JSON_BUILD_PAIR_ARRAY("selfModifiableFields", SD_JSON_BUILD_STRING("notInHardCodedList")));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_ARRAY("selfModifiableFields", SD_JSON_BUILD_STRING("notInHardCodedList")),
             /* change in order shouldn't affect things */
             SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 99999));
        assert_se(user_record_self_changes_allowed(curr, new));

        /* default allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_STRING("realName", "Old Name"));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_STRING("realName", "New Name"));
        assert_se(user_record_self_changes_allowed(curr, new));

        /* introduced new default allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_STRING("realName", "New Name"));
        assert_se(user_record_self_changes_allowed(curr, new));

        /* introduced new not allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 99999));
        assert_se(!user_record_self_changes_allowed(curr, new));

        /* privileged section: default allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_STRING("passwordHint", "Old Hint")));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_STRING("passwordHint", "New Hint")));
        assert_se(user_record_self_changes_allowed(curr, new));

        /* privileged section: not allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 11111)));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 99999)));
        assert_se(!user_record_self_changes_allowed(curr, new));

        /* privileged section: manually allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_ARRAY("selfModifiablePrivileged", SD_JSON_BUILD_STRING("notInHardCodedList")),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 11111)));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_ARRAY("selfModifiablePrivileged", SD_JSON_BUILD_STRING("notInHardCodedList")),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 99999)));
        assert_se(user_record_self_changes_allowed(curr, new));
}

DEFINE_TEST_MAIN(LOG_INFO);
