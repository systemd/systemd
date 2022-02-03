/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "user-record.h"
#include "group-record.h"

int user_record_synthesize(UserRecord *h, const char *user_name, const char *realm, const char *image_path, UserStorage storage, uid_t uid, gid_t gid);
int group_record_synthesize(GroupRecord *g, UserRecord *u);

typedef enum UserReconcileMode {
        USER_RECONCILE_ANY,
        USER_RECONCILE_REQUIRE_NEWER,          /* host version must be newer than embedded version */
        USER_RECONCILE_REQUIRE_NEWER_OR_EQUAL, /* similar, but may also be equal */
        _USER_RECONCILE_MODE_MAX,
        _USER_RECONCILE_MODE_INVALID = -EINVAL,
} UserReconcileMode;

enum { /* return values */
        USER_RECONCILE_HOST_WON,
        USER_RECONCILE_EMBEDDED_WON,
        USER_RECONCILE_IDENTICAL,
};

int user_record_reconcile(UserRecord *host, UserRecord *embedded, UserReconcileMode mode, UserRecord **ret);
int user_record_add_binding(UserRecord *h, UserStorage storage, const char *image_path, sd_id128_t partition_uuid, sd_id128_t luks_uuid, sd_id128_t fs_uuid, const char *luks_cipher, const char *luks_cipher_mode, uint64_t luks_volume_key_size, const char *file_system_type, const char *home_directory, uid_t uid, gid_t gid);

/* Results of the two test functions below. */
enum {
        USER_TEST_UNDEFINED, /* Returned by user_record_test_image_path() if the storage type knows no image paths */
        USER_TEST_ABSENT,
        USER_TEST_EXISTS,
        USER_TEST_DIRTY,     /* Only applies to user_record_test_image_path(), when the image exists but is marked dirty */
        USER_TEST_MOUNTED,   /* Only applies to user_record_test_home_directory(), when the home directory exists. */
        USER_TEST_MAYBE,     /* Only applies to LUKS devices: block device exists, but we don't know if it's the right one */
};

int user_record_test_home_directory(UserRecord *h);
int user_record_test_home_directory_and_warn(UserRecord *h);
int user_record_test_image_path(UserRecord *h);
int user_record_test_image_path_and_warn(UserRecord *h);

int user_record_test_password(UserRecord *h, UserRecord *secret);
int user_record_test_recovery_key(UserRecord *h, UserRecord *secret);

int user_record_update_last_changed(UserRecord *h, bool with_password);
int user_record_set_disk_size(UserRecord *h, uint64_t disk_size);
int user_record_set_password(UserRecord *h, char **password, bool prepend);
int user_record_make_hashed_password(UserRecord *h, char **password, bool extend);
int user_record_set_hashed_password(UserRecord *h, char **hashed_password);
int user_record_set_token_pin(UserRecord *h, char **pin, bool prepend);
int user_record_set_pkcs11_protected_authentication_path_permitted(UserRecord *h, int b);
int user_record_set_fido2_user_presence_permitted(UserRecord *h, int b);
int user_record_set_fido2_user_verification_permitted(UserRecord *h, int b);
int user_record_set_password_change_now(UserRecord *h, int b);
int user_record_merge_secret(UserRecord *h, UserRecord *secret);
int user_record_good_authentication(UserRecord *h);
int user_record_bad_authentication(UserRecord *h);
int user_record_ratelimit(UserRecord *h);

int user_record_is_supported(UserRecord *hr, sd_bus_error *error);

bool user_record_shall_rebalance(UserRecord *h);
int user_record_set_rebalance_weight(UserRecord *h, uint64_t weight);
