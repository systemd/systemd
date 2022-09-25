/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/types.h>

#include "sd-id128.h"

#include "json.h"
#include "missing_resource.h"
#include "time-util.h"

typedef enum UserDisposition {
        USER_INTRINSIC,   /* root and nobody */
        USER_SYSTEM,      /* statically allocated users for system services */
        USER_DYNAMIC,     /* dynamically allocated users for system services */
        USER_REGULAR,     /* regular (typically human users) */
        USER_CONTAINER,   /* UID ranges allocated for container uses */
        USER_RESERVED,    /* Range above 2^31 */
        _USER_DISPOSITION_MAX,
        _USER_DISPOSITION_INVALID = -EINVAL,
} UserDisposition;

typedef enum UserHomeStorage {
        USER_CLASSIC,
        USER_LUKS,
        USER_DIRECTORY, /* A directory, and a .identity file in it, which USER_CLASSIC lacks */
        USER_SUBVOLUME,
        USER_FSCRYPT,
        USER_CIFS,
        _USER_STORAGE_MAX,
        _USER_STORAGE_INVALID = -EINVAL,
} UserStorage;

typedef enum UserRecordMask {
        /* The various sections an identity record may have, as bit mask */
        USER_RECORD_REGULAR     = 1U << 0,
        USER_RECORD_SECRET      = 1U << 1,
        USER_RECORD_PRIVILEGED  = 1U << 2,
        USER_RECORD_PER_MACHINE = 1U << 3,
        USER_RECORD_BINDING     = 1U << 4,
        USER_RECORD_STATUS      = 1U << 5,
        USER_RECORD_SIGNATURE   = 1U << 6,
        _USER_RECORD_MASK_MAX   = (1U << 7)-1
} UserRecordMask;

typedef enum UserRecordLoadFlags {
        /* A set of flags used while loading a user record from JSON data. We leave the lower 6 bits free,
         * just as a safety precaution so that we can detect borked conversions between UserRecordMask and
         * UserRecordLoadFlags. */

        /* What to require */
        USER_RECORD_REQUIRE_REGULAR     = USER_RECORD_REGULAR     << 7,
        USER_RECORD_REQUIRE_SECRET      = USER_RECORD_SECRET      << 7,
        USER_RECORD_REQUIRE_PRIVILEGED  = USER_RECORD_PRIVILEGED  << 7,
        USER_RECORD_REQUIRE_PER_MACHINE = USER_RECORD_PER_MACHINE << 7,
        USER_RECORD_REQUIRE_BINDING     = USER_RECORD_BINDING     << 7,
        USER_RECORD_REQUIRE_STATUS      = USER_RECORD_STATUS      << 7,
        USER_RECORD_REQUIRE_SIGNATURE   = USER_RECORD_SIGNATURE   << 7,

        /* What to allow */
        USER_RECORD_ALLOW_REGULAR       = USER_RECORD_REGULAR     << 14,
        USER_RECORD_ALLOW_SECRET        = USER_RECORD_SECRET      << 14,
        USER_RECORD_ALLOW_PRIVILEGED    = USER_RECORD_PRIVILEGED  << 14,
        USER_RECORD_ALLOW_PER_MACHINE   = USER_RECORD_PER_MACHINE << 14,
        USER_RECORD_ALLOW_BINDING       = USER_RECORD_BINDING     << 14,
        USER_RECORD_ALLOW_STATUS        = USER_RECORD_STATUS      << 14,
        USER_RECORD_ALLOW_SIGNATURE     = USER_RECORD_SIGNATURE   << 14,

        /* What to strip */
        USER_RECORD_STRIP_REGULAR       = USER_RECORD_REGULAR     << 21,
        USER_RECORD_STRIP_SECRET        = USER_RECORD_SECRET      << 21,
        USER_RECORD_STRIP_PRIVILEGED    = USER_RECORD_PRIVILEGED  << 21,
        USER_RECORD_STRIP_PER_MACHINE   = USER_RECORD_PER_MACHINE << 21,
        USER_RECORD_STRIP_BINDING       = USER_RECORD_BINDING     << 21,
        USER_RECORD_STRIP_STATUS        = USER_RECORD_STATUS      << 21,
        USER_RECORD_STRIP_SIGNATURE     = USER_RECORD_SIGNATURE   << 21,

        /* Some special combinations that deserve explicit names */
        USER_RECORD_LOAD_FULL           = USER_RECORD_REQUIRE_REGULAR |
                                          USER_RECORD_ALLOW_SECRET |
                                          USER_RECORD_ALLOW_PRIVILEGED |
                                          USER_RECORD_ALLOW_PER_MACHINE |
                                          USER_RECORD_ALLOW_BINDING |
                                          USER_RECORD_ALLOW_STATUS |
                                          USER_RECORD_ALLOW_SIGNATURE,

        USER_RECORD_LOAD_REFUSE_SECRET =  USER_RECORD_REQUIRE_REGULAR |
                                          USER_RECORD_ALLOW_PRIVILEGED |
                                          USER_RECORD_ALLOW_PER_MACHINE |
                                          USER_RECORD_ALLOW_BINDING |
                                          USER_RECORD_ALLOW_STATUS |
                                          USER_RECORD_ALLOW_SIGNATURE,

        USER_RECORD_LOAD_MASK_SECRET =    USER_RECORD_REQUIRE_REGULAR |
                                          USER_RECORD_ALLOW_PRIVILEGED |
                                          USER_RECORD_ALLOW_PER_MACHINE |
                                          USER_RECORD_ALLOW_BINDING |
                                          USER_RECORD_ALLOW_STATUS |
                                          USER_RECORD_ALLOW_SIGNATURE |
                                          USER_RECORD_STRIP_SECRET,

        USER_RECORD_EXTRACT_SECRET      = USER_RECORD_REQUIRE_SECRET |
                                          USER_RECORD_STRIP_REGULAR |
                                          USER_RECORD_STRIP_PRIVILEGED |
                                          USER_RECORD_STRIP_PER_MACHINE |
                                          USER_RECORD_STRIP_BINDING |
                                          USER_RECORD_STRIP_STATUS |
                                          USER_RECORD_STRIP_SIGNATURE,

        USER_RECORD_LOAD_SIGNABLE       = USER_RECORD_REQUIRE_REGULAR |
                                          USER_RECORD_ALLOW_PRIVILEGED |
                                          USER_RECORD_ALLOW_PER_MACHINE,

        USER_RECORD_EXTRACT_SIGNABLE    = USER_RECORD_LOAD_SIGNABLE |
                                          USER_RECORD_STRIP_SECRET |
                                          USER_RECORD_STRIP_BINDING |
                                          USER_RECORD_STRIP_STATUS |
                                          USER_RECORD_STRIP_SIGNATURE,

        USER_RECORD_LOAD_EMBEDDED       = USER_RECORD_REQUIRE_REGULAR |
                                          USER_RECORD_ALLOW_PRIVILEGED |
                                          USER_RECORD_ALLOW_PER_MACHINE |
                                          USER_RECORD_ALLOW_SIGNATURE,

        USER_RECORD_EXTRACT_EMBEDDED    = USER_RECORD_LOAD_EMBEDDED |
                                          USER_RECORD_STRIP_SECRET |
                                          USER_RECORD_STRIP_BINDING |
                                          USER_RECORD_STRIP_STATUS,

        /* Whether to log about loader errors beyond LOG_DEBUG */
        USER_RECORD_LOG                 = 1U << 28,

        /* Whether to ignore errors and load what we can */
        USER_RECORD_PERMISSIVE          = 1U << 29,

        /* Whether an empty record is OK */
        USER_RECORD_EMPTY_OK            = 1U << 30,
} UserRecordLoadFlags;

static inline UserRecordLoadFlags USER_RECORD_REQUIRE(UserRecordMask m) {
        assert((m & ~_USER_RECORD_MASK_MAX) == 0);
        return m << 7;
}

static inline UserRecordLoadFlags USER_RECORD_ALLOW(UserRecordMask m) {
        assert((m & ~_USER_RECORD_MASK_MAX) == 0);
        return m << 14;
}

static inline UserRecordLoadFlags USER_RECORD_STRIP(UserRecordMask m) {
        assert((m & ~_USER_RECORD_MASK_MAX) == 0);
        return m << 21;
}

static inline UserRecordMask USER_RECORD_REQUIRE_MASK(UserRecordLoadFlags f) {
        return (f >> 7) & _USER_RECORD_MASK_MAX;
}

static inline UserRecordMask USER_RECORD_ALLOW_MASK(UserRecordLoadFlags f) {
        return ((f >> 14) & _USER_RECORD_MASK_MAX) | USER_RECORD_REQUIRE_MASK(f);
}

static inline UserRecordMask USER_RECORD_STRIP_MASK(UserRecordLoadFlags f) {
        return (f >> 21) & _USER_RECORD_MASK_MAX;
}

static inline JsonDispatchFlags USER_RECORD_LOAD_FLAGS_TO_JSON_DISPATCH_FLAGS(UserRecordLoadFlags flags) {
        return (FLAGS_SET(flags, USER_RECORD_LOG) ? JSON_LOG : 0) |
                (FLAGS_SET(flags, USER_RECORD_PERMISSIVE) ? JSON_PERMISSIVE : 0);
}

typedef struct Pkcs11EncryptedKey {
        /* The encrypted passphrase, which can be decrypted with the private key indicated below */
        void *data;
        size_t size;

        /* Where to find the private key to decrypt the encrypted passphrase above */
        char *uri;

        /* What to test the decrypted passphrase against to allow access (classic UNIX password hash).  Note
         * that the decrypted passphrase is also used for unlocking LUKS and fscrypt, and if the account is
         * backed by LUKS or fscrypt the hashed password is only an additional layer of authentication, not
         * the only. */
        char *hashed_password;
} Pkcs11EncryptedKey;

typedef struct Fido2HmacCredential {
        void *id;
        size_t size;
} Fido2HmacCredential;

typedef struct Fido2HmacSalt {
        /* The FIDO2 Cridential ID to use */
        Fido2HmacCredential credential;

        /* The FIDO2 salt value */
        void *salt;
        size_t salt_size;

        /* What to test the hashed salt value against, usually UNIX password hash here. */
        char *hashed_password;

        /* Whether the 'up', 'uv', 'clientPin' features are enabled. */
        int uv, up, client_pin;
} Fido2HmacSalt;

typedef struct RecoveryKey {
        /* The type of recovery key, must be "modhex64" right now */
        char *type;

        /* A UNIX password hash of the normalized form of modhex64 */
        char *hashed_password;
} RecoveryKey;

typedef enum AutoResizeMode {
        AUTO_RESIZE_OFF,               /* no automatic grow/shrink */
        AUTO_RESIZE_GROW,              /* grow at login */
        AUTO_RESIZE_SHRINK_AND_GROW,   /* shrink at logout + grow at login */
        _AUTO_RESIZE_MODE_MAX,
        _AUTO_RESIZE_MODE_INVALID = -EINVAL,
} AutoResizeMode;

#define REBALANCE_WEIGHT_OFF UINT64_C(0)
#define REBALANCE_WEIGHT_DEFAULT UINT64_C(100)
#define REBALANCE_WEIGHT_BACKING UINT64_C(20)
#define REBALANCE_WEIGHT_MIN UINT64_C(1)
#define REBALANCE_WEIGHT_MAX UINT64_C(10000)
#define REBALANCE_WEIGHT_UNSET UINT64_MAX

typedef struct UserRecord {
        /* The following three fields are not part of the JSON record */
        unsigned n_ref;
        UserRecordMask mask;
        bool incomplete; /* incomplete due to security restrictions. */

        char *user_name;
        char *realm;
        char *user_name_and_realm_auto; /* the user_name field concatenated with '@' and the realm, if the latter is defined */
        char *real_name;
        char *email_address;
        char *password_hint;
        char *icon_name;
        char *location;

        UserDisposition disposition;
        uint64_t last_change_usec;
        uint64_t last_password_change_usec;

        char *shell;
        mode_t umask;
        char **environment;
        char *time_zone;
        char *preferred_language;
        int nice_level;
        struct rlimit *rlimits[_RLIMIT_MAX];

        int locked;               /* prohibit activation in general */
        uint64_t not_before_usec; /* prohibit activation before this unix time */
        uint64_t not_after_usec;  /* prohibit activation after this unix time */

        UserStorage storage;
        uint64_t disk_size;
        uint64_t disk_size_relative; /* Disk size, relative to the free bytes of the medium, normalized to UINT32_MAX = 100% */
        char *skeleton_directory;
        mode_t access_mode;
        AutoResizeMode auto_resize_mode;
        uint64_t rebalance_weight;

        uint64_t tasks_max;
        uint64_t memory_high;
        uint64_t memory_max;
        uint64_t cpu_weight;
        uint64_t io_weight;

        bool nosuid;
        bool nodev;
        bool noexec;

        char **hashed_password;
        char **ssh_authorized_keys;
        char **password;
        char **token_pin;

        char *cifs_domain;
        char *cifs_user_name;
        char *cifs_service;
        char *cifs_extra_mount_options;

        char *image_path;
        char *image_path_auto; /* when none is configured explicitly, this is where we place the implicit image */
        char *home_directory;
        char *home_directory_auto; /* when none is set explicitly, this is where we place the implicit home directory */

        uid_t uid;
        gid_t gid;

        char **member_of;

        char *file_system_type;
        sd_id128_t partition_uuid;
        sd_id128_t luks_uuid;
        sd_id128_t file_system_uuid;

        int luks_discard;
        int luks_offline_discard;
        char *luks_cipher;
        char *luks_cipher_mode;
        uint64_t luks_volume_key_size;
        char *luks_pbkdf_hash_algorithm;
        char *luks_pbkdf_type;
        uint64_t luks_pbkdf_time_cost_usec;
        uint64_t luks_pbkdf_memory_cost;
        uint64_t luks_pbkdf_parallel_threads;
        uint64_t luks_sector_size;
        char *luks_extra_mount_options;

        uint64_t disk_usage;
        uint64_t disk_free;
        uint64_t disk_ceiling;
        uint64_t disk_floor;

        char *state;
        char *service;
        int signed_locally;

        uint64_t good_authentication_counter;
        uint64_t bad_authentication_counter;
        uint64_t last_good_authentication_usec;
        uint64_t last_bad_authentication_usec;

        uint64_t ratelimit_begin_usec;
        uint64_t ratelimit_count;
        uint64_t ratelimit_interval_usec;
        uint64_t ratelimit_burst;

        int removable;
        int enforce_password_policy;
        int auto_login;
        int drop_caches;

        uint64_t stop_delay_usec;   /* How long to leave systemd --user around on log-out */
        int kill_processes;         /* Whether to kill user processes forcibly on log-out */

        /* The following exist mostly so that we can cover the full /etc/shadow set of fields */
        uint64_t password_change_min_usec;       /* maps to .sp_min */
        uint64_t password_change_max_usec;       /* maps to .sp_max */
        uint64_t password_change_warn_usec;      /* maps to .sp_warn */
        uint64_t password_change_inactive_usec;  /* maps to .sp_inact */
        int password_change_now;                 /* Require a password change immediately on next login (.sp_lstchg = 0) */

        char **pkcs11_token_uri;
        Pkcs11EncryptedKey *pkcs11_encrypted_key;
        size_t n_pkcs11_encrypted_key;
        int pkcs11_protected_authentication_path_permitted;

        Fido2HmacCredential *fido2_hmac_credential;
        size_t n_fido2_hmac_credential;
        Fido2HmacSalt *fido2_hmac_salt;
        size_t n_fido2_hmac_salt;
        int fido2_user_presence_permitted;
        int fido2_user_verification_permitted;

        char **recovery_key_type;
        RecoveryKey *recovery_key;
        size_t n_recovery_key;

        JsonVariant *json;
} UserRecord;

UserRecord* user_record_new(void);
UserRecord* user_record_ref(UserRecord *h);
UserRecord* user_record_unref(UserRecord *h);

DEFINE_TRIVIAL_CLEANUP_FUNC(UserRecord*, user_record_unref);

int user_record_load(UserRecord *h, JsonVariant *v, UserRecordLoadFlags flags);
int user_record_build(UserRecord **ret, ...);

const char *user_record_user_name_and_realm(UserRecord *h);
UserStorage user_record_storage(UserRecord *h);
const char *user_record_file_system_type(UserRecord *h);
const char *user_record_skeleton_directory(UserRecord *h);
mode_t user_record_access_mode(UserRecord *h);
const char *user_record_home_directory(UserRecord *h);
const char *user_record_image_path(UserRecord *h);
unsigned long user_record_mount_flags(UserRecord *h);
const char *user_record_cifs_user_name(UserRecord *h);
const char *user_record_shell(UserRecord *h);
const char *user_record_real_name(UserRecord *h);
bool user_record_luks_discard(UserRecord *h);
bool user_record_luks_offline_discard(UserRecord *h);
const char *user_record_luks_cipher(UserRecord *h);
const char *user_record_luks_cipher_mode(UserRecord *h);
uint64_t user_record_luks_volume_key_size(UserRecord *h);
const char* user_record_luks_pbkdf_type(UserRecord *h);
usec_t user_record_luks_pbkdf_time_cost_usec(UserRecord *h);
uint64_t user_record_luks_pbkdf_memory_cost(UserRecord *h);
uint64_t user_record_luks_pbkdf_parallel_threads(UserRecord *h);
uint64_t user_record_luks_sector_size(UserRecord *h);
const char *user_record_luks_pbkdf_hash_algorithm(UserRecord *h);
gid_t user_record_gid(UserRecord *h);
UserDisposition user_record_disposition(UserRecord *h);
int user_record_removable(UserRecord *h);
usec_t user_record_ratelimit_interval_usec(UserRecord *h);
uint64_t user_record_ratelimit_burst(UserRecord *h);
bool user_record_can_authenticate(UserRecord *h);
bool user_record_drop_caches(UserRecord *h);
AutoResizeMode user_record_auto_resize_mode(UserRecord *h);
uint64_t user_record_rebalance_weight(UserRecord *h);

int user_record_build_image_path(UserStorage storage, const char *user_name_and_realm, char **ret);

bool user_record_equal(UserRecord *a, UserRecord *b);
bool user_record_compatible(UserRecord *a, UserRecord *b);
int user_record_compare_last_change(UserRecord *a, UserRecord *b);

usec_t user_record_ratelimit_next_try(UserRecord *h);

int user_record_clone(UserRecord *h, UserRecordLoadFlags flags, UserRecord **ret);
int user_record_masked_equal(UserRecord *a, UserRecord *b, UserRecordMask mask);

int user_record_test_blocked(UserRecord *h);
int user_record_test_password_change_required(UserRecord *h);

/* The following six are user by group-record.c, that's why we export them here */
int json_dispatch_realm(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_gecos(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_user_group_list(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_user_disposition(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);

int per_machine_id_match(JsonVariant *ids, JsonDispatchFlags flags);
int per_machine_hostname_match(JsonVariant *hns, JsonDispatchFlags flags);
int user_group_record_mangle(JsonVariant *v, UserRecordLoadFlags load_flags, JsonVariant **ret_variant, UserRecordMask *ret_mask);

const char* user_storage_to_string(UserStorage t) _const_;
UserStorage user_storage_from_string(const char *s) _pure_;

const char* user_disposition_to_string(UserDisposition t) _const_;
UserDisposition user_disposition_from_string(const char *s) _pure_;

const char* auto_resize_mode_to_string(AutoResizeMode m) _const_;
AutoResizeMode auto_resize_mode_from_string(const char *s) _pure_;
