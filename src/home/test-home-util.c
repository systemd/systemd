/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"
#include "sd-json.h"

#include "errno-util.h"
#include "fileio.h"
#include "home-util.h"
#include "id128-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-record.h"
#include "user-record-util.h"

TEST(record_commit_pending) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_free_ char *contents = NULL, *final = NULL, *intent = NULL, *pending = NULL;

        ASSERT_OK(mkdtemp_malloc(NULL, &d));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_HOME_RECORD_DIR", d, /* overwrite= */ true));

        pending = path_join(d, "alice" HOME_RECORD_PENDING_SUFFIX);
        intent = path_join(d, "alice" HOME_RECORD_THIN_INTENT_SUFFIX);
        final = path_join(d, "alice" HOME_RECORD_SUFFIX);
        ASSERT_NOT_NULL(pending);
        ASSERT_NOT_NULL(intent);
        ASSERT_NOT_NULL(final);

        ASSERT_OK(write_string_file(pending, "pending", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(home_record_commit_pending("alice"));
        ASSERT_OK_ERRNO(access(final, F_OK));
        ASSERT_ERROR_ERRNO(access(pending, F_OK), ENOENT);

        ASSERT_OK(read_full_file(final, &contents, /* ret_size= */ NULL));
        ASSERT_STREQ(contents, "pending\n");

        ASSERT_OK(write_string_file(pending, "new", WRITE_STRING_FILE_CREATE));
        ASSERT_ERROR(home_record_commit_pending("alice"), EEXIST);

        ASSERT_OK(write_string_file(intent, "intent", WRITE_STRING_FILE_CREATE));
        ASSERT_EQ(home_record_has_pending("alice"), 1);
        ASSERT_OK(home_record_cancel_pending("alice"));
        ASSERT_ERROR_ERRNO(access(pending, F_OK), ENOENT);
        ASSERT_ERROR_ERRNO(access(intent, F_OK), ENOENT);
        ASSERT_EQ(home_record_has_pending("alice"), 0);

        contents = mfree(contents);
        ASSERT_OK(read_full_file(final, &contents, /* ret_size= */ NULL));
        ASSERT_STREQ(contents, "pending\n");
}

TEST(incomplete_thin_binding) {
        _cleanup_(user_record_unrefp) UserRecord *clone = NULL, *u = NULL;
        sd_id128_t creation_id = SD_ID128_MAKE(51,df,0b,4b,c3,b0,4c,97,80,e2,99,b9,8c,a3,73,b8),
                loaded_creation_id, mid;
        int r;

        r = sd_id128_get_machine(&mid);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return (void) log_tests_skipped("/etc/machine-id missing");
        ASSERT_OK(r);

        ASSERT_OK(user_record_build(
                        &u,
                        SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("disposition", "regular"),
                                        SD_JSON_BUILD_PAIR_STRING("userName", "alice"),
                                        SD_JSON_BUILD_PAIR_OBJECT(
                                                        "binding",
                                                        SD_JSON_BUILD_PAIR_OBJECT(
                                                                        SD_ID128_TO_STRING(mid),
                                                                        SD_JSON_BUILD_PAIR_STRING("storage", "luks"),
                                                                        SD_JSON_BUILD_PAIR_STRING("luksKeyType", "hw-wrapped"),
                                                                        SD_JSON_BUILD_PAIR_STRING(
                                                                                        "imagePath",
                                                                                        "/dev/homes/homed-alice"))))));

        ASSERT_OK(user_record_add_thin_pool_binding(u, "HOMED-POOL-test", 42));
        ASSERT_STREQ(u->thin_pool_uuid, "HOMED-POOL-test");
        ASSERT_EQ(u->thin_device_id, 42U);
        ASSERT_STREQ(u->luks_key_type, "hw-wrapped");
        ASSERT_NULL(u->luks_integrity);

        ASSERT_OK(user_record_set_thin_volume_creation_id(u, creation_id));
        ASSERT_OK(user_record_get_thin_volume_creation_id(u, &loaded_creation_id));
        ASSERT_EQ_ID128(loaded_creation_id, creation_id);

        ASSERT_OK(user_record_clone(u, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_PERMISSIVE, &clone));
        ASSERT_STREQ(clone->thin_pool_uuid, "HOMED-POOL-test");
        ASSERT_EQ(clone->thin_device_id, 42U);
        ASSERT_STREQ(clone->luks_key_type, "hw-wrapped");
        ASSERT_NULL(clone->luks_integrity);
        ASSERT_OK(user_record_get_thin_volume_creation_id(clone, &loaded_creation_id));
        ASSERT_EQ_ID128(loaded_creation_id, creation_id);
}

TEST(protected_thin_binding) {
        _cleanup_(user_record_unrefp) UserRecord *clone = NULL, *u = NULL;
        sd_id128_t mid;
        int r;

        r = sd_id128_get_machine(&mid);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return (void) log_tests_skipped("/etc/machine-id missing");
        ASSERT_OK(r);

        ASSERT_OK(user_record_build(
                        &u,
                        SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("disposition", "regular"),
                                        SD_JSON_BUILD_PAIR_STRING("userName", "alice"),
                                        SD_JSON_BUILD_PAIR_OBJECT(
                                                        "binding",
                                                        SD_JSON_BUILD_PAIR_OBJECT(
                                                                        SD_ID128_TO_STRING(mid),
                                                                        SD_JSON_BUILD_PAIR_STRING("storage", "luks"),
                                                                        SD_JSON_BUILD_PAIR_STRING("luksKeyType", "hw-wrapped"),
                                                                        SD_JSON_BUILD_PAIR_STRING(
                                                                                        "imagePath",
                                                                                        "/dev/homes/homed-alice"))))));

        ASSERT_OK(user_record_set_luks_integrity_binding(u, "hmac(sha256)"));
        ASSERT_STREQ(u->luks_integrity, "hmac(sha256)");

        ASSERT_OK(user_record_clone(u, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_PERMISSIVE, &clone));
        ASSERT_STREQ(clone->luks_integrity, "hmac(sha256)");

        ASSERT_OK(user_record_set_luks_integrity_binding(clone, NULL));
        ASSERT_NULL(clone->luks_integrity);
}

DEFINE_TEST_MAIN(LOG_INFO);
