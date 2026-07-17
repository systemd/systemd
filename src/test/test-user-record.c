/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"
#include "sd-json.h"

#include "id128-util.h"
#include "tests.h"
#include "user-record.h"

#define USER(ret, ...)                          \
        ({                                      \
                typeof(ret) _r = (ret);         \
                user_record_unref(*_r);         \
                ASSERT_OK(user_record_build((ret), SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_STRING("disposition", "regular"), __VA_ARGS__))); \
                0;                              \
        })

TEST(shell_validation) {
        static const char * const invalid_shells[] = {
                "sh",
                "/bin/sh\nbad",
                "/bin/sh:bad",
                "/bin/sh/",
        };

        _cleanup_(user_record_unrefp) UserRecord *u = NULL;
        sd_id128_t mid;
        int r;

        FOREACH_ELEMENT(shell, invalid_shells) {
                ASSERT_ERROR(user_record_build(
                                             &u,
                                             SD_JSON_BUILD_OBJECT(
                                                             SD_JSON_BUILD_PAIR_STRING("disposition", "regular"),
                                                             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
                                                             SD_JSON_BUILD_PAIR_STRING("shell", *shell))),
                             EINVAL);
                ASSERT_NULL(u);
        }

        r = sd_id128_get_machine(&mid);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return (void) log_tests_skipped("/etc/machine-id missing");
        ASSERT_OK(r);

        FOREACH_ELEMENT(shell, invalid_shells) {
                ASSERT_ERROR(user_record_build(
                                             &u,
                                             SD_JSON_BUILD_OBJECT(
                                                             SD_JSON_BUILD_PAIR_STRING("disposition", "regular"),
                                                             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
                                                             SD_JSON_BUILD_PAIR_ARRAY(
                                                                             "perMachine",
                                                                             SD_JSON_BUILD_OBJECT(
                                                                                             SD_JSON_BUILD_PAIR_ID128("matchMachineId", mid),
                                                                                             SD_JSON_BUILD_PAIR_STRING("shell", *shell))))),
                             EINVAL);
                ASSERT_NULL(u);

                ASSERT_ERROR(user_record_build(
                                             &u,
                                             SD_JSON_BUILD_OBJECT(
                                                             SD_JSON_BUILD_PAIR_STRING("disposition", "regular"),
                                                             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
                                                             SD_JSON_BUILD_PAIR_OBJECT(
                                                                             "status",
                                                                             SD_JSON_BUILD_PAIR_OBJECT(
                                                                                             SD_ID128_TO_STRING(mid),
                                                                                             SD_JSON_BUILD_PAIR_STRING("fallbackShell", *shell))))),
                             EINVAL);
                ASSERT_NULL(u);
        }

        USER(&u,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_STRING("shell", "/bin/sh"),
             SD_JSON_BUILD_PAIR_ARRAY(
                             "perMachine",
                             SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_ID128("matchMachineId", mid),
                                             SD_JSON_BUILD_PAIR_STRING("shell", "/bin/bash"))),
             SD_JSON_BUILD_PAIR_OBJECT(
                             "status",
                             SD_JSON_BUILD_PAIR_OBJECT(
                                             SD_ID128_TO_STRING(mid),
                                             SD_JSON_BUILD_PAIR_STRING("fallbackShell", "/bin/zsh"),
                                             SD_JSON_BUILD_PAIR_BOOLEAN("useFallback", true))));
        ASSERT_STREQ(u->shell, "/bin/bash");
        ASSERT_STREQ(u->fallback_shell, "/bin/zsh");
        ASSERT_STREQ(user_record_shell(u), "/bin/zsh");
}

TEST(self_changes) {
        _cleanup_(user_record_unrefp) UserRecord *curr = NULL, *new = NULL;

        /* not allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 11111));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 99999));
        ASSERT_FALSE(user_record_self_changes_allowed(curr, new));

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
        ASSERT_TRUE(user_record_self_changes_allowed(curr, new));

        /* default allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_STRING("realName", "Old Name"));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_STRING("realName", "New Name"));
        ASSERT_TRUE(user_record_self_changes_allowed(curr, new));

        /* introduced new default allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_STRING("realName", "New Name"));
        ASSERT_TRUE(user_record_self_changes_allowed(curr, new));

        /* introduced new not allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 99999));
        ASSERT_FALSE(user_record_self_changes_allowed(curr, new));

        /* privileged section: default allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_STRING("passwordHint", "Old Hint")));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_STRING("passwordHint", "New Hint")));
        ASSERT_TRUE(user_record_self_changes_allowed(curr, new));

        /* privileged section: not allowlisted */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 11111)));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_OBJECT("privileged",
                                    SD_JSON_BUILD_PAIR_UNSIGNED("notInHardCodedList", 99999)));
        ASSERT_FALSE(user_record_self_changes_allowed(curr, new));

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
        ASSERT_TRUE(user_record_self_changes_allowed(curr, new));

        /* birthDate is NOT self-modifiable (admin-only) */
        USER(&curr,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_STRING("birthDate", "1990-01-01"));
        USER(&new,
             SD_JSON_BUILD_PAIR_STRING("userName", "test"),
             SD_JSON_BUILD_PAIR_STRING("birthDate", "1990-06-15"));
        ASSERT_FALSE(user_record_self_changes_allowed(curr, new));
}

DEFINE_TEST_MAIN(LOG_INFO);
