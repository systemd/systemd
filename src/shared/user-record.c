/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "cap-list.h"
#include "cgroup-util.h"
#include "dns-domain.h"
#include "env-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "memory-util.h"
#include "path-util.h"
#include "pkcs11-util.h"
#include "rlimit-util.h"
#include "string-table.h"
#include "strv.h"
#include "uid-alloc-range.h"
#include "user-record.h"
#include "user-util.h"

#define DEFAULT_RATELIMIT_BURST 30
#define DEFAULT_RATELIMIT_INTERVAL_USEC (1*USEC_PER_MINUTE)

UserRecord* user_record_new(void) {
        UserRecord *h;

        h = new(UserRecord, 1);
        if (!h)
                return NULL;

        *h = (UserRecord) {
                .n_ref = 1,
                .disposition = _USER_DISPOSITION_INVALID,
                .last_change_usec = UINT64_MAX,
                .last_password_change_usec = UINT64_MAX,
                .umask = MODE_INVALID,
                .nice_level = INT_MAX,
                .not_before_usec = UINT64_MAX,
                .not_after_usec = UINT64_MAX,
                .locked = -1,
                .storage = _USER_STORAGE_INVALID,
                .access_mode = MODE_INVALID,
                .disk_size = UINT64_MAX,
                .disk_size_relative = UINT64_MAX,
                .tasks_max = UINT64_MAX,
                .memory_high = UINT64_MAX,
                .memory_max = UINT64_MAX,
                .cpu_weight = UINT64_MAX,
                .io_weight = UINT64_MAX,
                .uid = UID_INVALID,
                .gid = GID_INVALID,
                .nodev = true,
                .nosuid = true,
                .luks_discard = -1,
                .luks_offline_discard = -1,
                .luks_volume_key_size = UINT64_MAX,
                .luks_pbkdf_force_iterations = UINT64_MAX,
                .luks_pbkdf_time_cost_usec = UINT64_MAX,
                .luks_pbkdf_memory_cost = UINT64_MAX,
                .luks_pbkdf_parallel_threads = UINT64_MAX,
                .luks_sector_size = UINT64_MAX,
                .disk_usage = UINT64_MAX,
                .disk_free = UINT64_MAX,
                .disk_ceiling = UINT64_MAX,
                .disk_floor = UINT64_MAX,
                .signed_locally = -1,
                .good_authentication_counter = UINT64_MAX,
                .bad_authentication_counter = UINT64_MAX,
                .last_good_authentication_usec = UINT64_MAX,
                .last_bad_authentication_usec = UINT64_MAX,
                .ratelimit_begin_usec = UINT64_MAX,
                .ratelimit_count = UINT64_MAX,
                .ratelimit_interval_usec = UINT64_MAX,
                .ratelimit_burst = UINT64_MAX,
                .removable = -1,
                .enforce_password_policy = -1,
                .auto_login = -1,
                .stop_delay_usec = UINT64_MAX,
                .kill_processes = -1,
                .password_change_min_usec = UINT64_MAX,
                .password_change_max_usec = UINT64_MAX,
                .password_change_warn_usec = UINT64_MAX,
                .password_change_inactive_usec = UINT64_MAX,
                .password_change_now = -1,
                .pkcs11_protected_authentication_path_permitted = -1,
                .fido2_user_presence_permitted = -1,
                .fido2_user_verification_permitted = -1,
                .drop_caches = -1,
                .auto_resize_mode = _AUTO_RESIZE_MODE_INVALID,
                .rebalance_weight = REBALANCE_WEIGHT_UNSET,
        };

        return h;
}

static void pkcs11_encrypted_key_done(Pkcs11EncryptedKey *k) {
        if (!k)
                return;

        free(k->uri);
        erase_and_free(k->data);
        erase_and_free(k->hashed_password);
}

static void fido2_hmac_credential_done(Fido2HmacCredential *c) {
        if (!c)
                return;

        free(c->id);
}

static void fido2_hmac_salt_done(Fido2HmacSalt *s) {
        if (!s)
                return;

        fido2_hmac_credential_done(&s->credential);
        erase_and_free(s->salt);
        erase_and_free(s->hashed_password);
}

static void recovery_key_done(RecoveryKey *k) {
        if (!k)
                return;

        free(k->type);
        erase_and_free(k->hashed_password);
}

static UserRecord* user_record_free(UserRecord *h) {
        if (!h)
                return NULL;

        free(h->user_name);
        free(h->realm);
        free(h->user_name_and_realm_auto);
        free(h->real_name);
        free(h->email_address);
        erase_and_free(h->password_hint);
        free(h->location);
        free(h->icon_name);
        free(h->avatar_path);

        free(h->shell);

        strv_free(h->environment);
        free(h->time_zone);
        free(h->preferred_language);
        rlimit_free_all(h->rlimits);

        free(h->skeleton_directory);

        strv_free_erase(h->hashed_password);
        strv_free_erase(h->ssh_authorized_keys);
        strv_free_erase(h->password);
        strv_free_erase(h->token_pin);

        free(h->cifs_service);
        free(h->cifs_user_name);
        free(h->cifs_domain);
        free(h->cifs_extra_mount_options);

        free(h->image_path);
        free(h->image_path_auto);
        free(h->home_directory);
        free(h->home_directory_auto);

        strv_free(h->member_of);
        strv_free(h->capability_bounding_set);
        strv_free(h->capability_ambient_set);

        free(h->file_system_type);
        free(h->luks_cipher);
        free(h->luks_cipher_mode);
        free(h->luks_pbkdf_hash_algorithm);
        free(h->luks_pbkdf_type);
        free(h->luks_extra_mount_options);

        free(h->state);
        free(h->service);

        strv_free(h->pkcs11_token_uri);
        for (size_t i = 0; i < h->n_pkcs11_encrypted_key; i++)
                pkcs11_encrypted_key_done(h->pkcs11_encrypted_key + i);
        free(h->pkcs11_encrypted_key);

        for (size_t i = 0; i < h->n_fido2_hmac_credential; i++)
                fido2_hmac_credential_done(h->fido2_hmac_credential + i);
        for (size_t i = 0; i < h->n_fido2_hmac_salt; i++)
                fido2_hmac_salt_done(h->fido2_hmac_salt + i);

        strv_free(h->recovery_key_type);
        for (size_t i = 0; i < h->n_recovery_key; i++)
                recovery_key_done(h->recovery_key + i);

        json_variant_unref(h->json);

        return mfree(h);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(UserRecord, user_record, user_record_free);

int json_dispatch_realm(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        char **s = userdata;
        const char *n;
        int r;

        if (json_variant_is_null(variant)) {
                *s = mfree(*s);
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        n = json_variant_string(variant);
        r = dns_name_is_valid(n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to check if JSON field '%s' is a valid DNS domain.", strna(name));
        if (r == 0)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid DNS domain.", strna(name));

        r = free_and_strdup(s, n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

int json_dispatch_gecos(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        char **s = userdata;
        const char *n;

        if (json_variant_is_null(variant)) {
                *s = mfree(*s);
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        n = json_variant_string(variant);
        if (valid_gecos(n)) {
                if (free_and_strdup(s, n) < 0)
                        return json_log_oom(variant, flags);
        } else {
                _cleanup_free_ char *m = NULL;

                json_log(variant, flags|JSON_DEBUG, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid GECOS compatible string, mangling.", strna(name));

                m = mangle_gecos(n);
                if (!m)
                        return json_log_oom(variant, flags);

                free_and_replace(*s, m);
        }

        return 0;
}

static int json_dispatch_nice(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        int *nl = userdata;
        int64_t m;

        if (json_variant_is_null(variant)) {
                *nl = INT_MAX;
                return 0;
        }

        if (!json_variant_is_integer(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        m = json_variant_integer(variant);
        if (m < PRIO_MIN || m >= PRIO_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' is not a valid nice level.", strna(name));

        *nl = m;
        return 0;
}

static int json_dispatch_rlimit_value(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        rlim_t *ret = userdata;

        if (json_variant_is_null(variant))
                *ret = RLIM_INFINITY;
        else if (json_variant_is_unsigned(variant)) {
                uint64_t w;

                w = json_variant_unsigned(variant);
                if (w == RLIM_INFINITY || (uint64_t) w != json_variant_unsigned(variant))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "Resource limit value '%s' is out of range.", name);

                *ret = (rlim_t) w;
        } else
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Resource limit value '%s' is not an unsigned integer.", name);

        return 0;
}

static int json_dispatch_rlimits(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        struct rlimit** limits = userdata;
        JsonVariant *value;
        const char *key;
        int r;

        assert_se(limits);

        if (json_variant_is_null(variant)) {
                rlimit_free_all(limits);
                return 0;
        }

        if (!json_variant_is_object(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an object.", strna(name));

        JSON_VARIANT_OBJECT_FOREACH(key, value, variant) {
                JsonVariant *jcur, *jmax;
                struct rlimit rl;
                const char *p;
                int l;

                p = startswith(key, "RLIMIT_");
                if (!p)
                        l = -SYNTHETIC_ERRNO(EINVAL);
                else
                        l = rlimit_from_string(p);
                if (l < 0)
                        return json_log(variant, flags, l, "Resource limit '%s' not known.", key);

                if (!json_variant_is_object(value))
                        return json_log(value, flags, SYNTHETIC_ERRNO(EINVAL), "Resource limit '%s' has invalid value.", key);

                if (json_variant_elements(value) != 4)
                        return json_log(value, flags, SYNTHETIC_ERRNO(EINVAL), "Resource limit '%s' value is does not have two fields as expected.", key);

                jcur = json_variant_by_key(value, "cur");
                if (!jcur)
                        return json_log(value, flags, SYNTHETIC_ERRNO(EINVAL), "Resource limit '%s' lacks 'cur' field.", key);
                r = json_dispatch_rlimit_value("cur", jcur, flags, &rl.rlim_cur);
                if (r < 0)
                        return r;

                jmax = json_variant_by_key(value, "max");
                if (!jmax)
                        return json_log(value, flags, SYNTHETIC_ERRNO(EINVAL), "Resource limit '%s' lacks 'max' field.", key);
                r = json_dispatch_rlimit_value("max", jmax, flags, &rl.rlim_max);
                if (r < 0)
                        return r;

                if (limits[l])
                        *(limits[l]) = rl;
                else {
                        limits[l] = newdup(struct rlimit, &rl, 1);
                        if (!limits[l])
                                return log_oom();
                }
        }

        return 0;
}

static int json_dispatch_filename_or_path(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        char **s = ASSERT_PTR(userdata);
        const char *n;
        int r;

        if (json_variant_is_null(variant)) {
                *s = mfree(*s);
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        n = json_variant_string(variant);
        if (!filename_is_valid(n) && !path_is_normalized(n))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid file name or normalized path.", strna(name));

        r = free_and_strdup(s, n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

static int json_dispatch_path(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        char **s = userdata;
        const char *n;
        int r;

        if (json_variant_is_null(variant)) {
                *s = mfree(*s);
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        n = json_variant_string(variant);
        if (!path_is_normalized(n))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a normalized file system path.", strna(name));
        if (!path_is_absolute(n))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an absolute file system path.", strna(name));

        r = free_and_strdup(s, n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

static int json_dispatch_home_directory(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        char **s = userdata;
        const char *n;
        int r;

        if (json_variant_is_null(variant)) {
                *s = mfree(*s);
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        n = json_variant_string(variant);
        if (!valid_home(n))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid home directory path.", strna(name));

        r = free_and_strdup(s, n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

static int json_dispatch_image_path(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        char **s = userdata;
        const char *n;
        int r;

        if (json_variant_is_null(variant)) {
                *s = mfree(*s);
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        n = json_variant_string(variant);
        if (empty_or_root(n) || !path_is_valid(n) || !path_is_absolute(n))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid image path.", strna(name));

        r = free_and_strdup(s, n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

static int json_dispatch_umask(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        mode_t *m = userdata;
        uint64_t k;

        if (json_variant_is_null(variant)) {
                *m = MODE_INVALID;
                return 0;
        }

        if (!json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a number.", strna(name));

        k = json_variant_unsigned(variant);
        if (k > 0777)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                "JSON field '%s' outside of valid range 0%s0777.",
                                strna(name), special_glyph(SPECIAL_GLYPH_ELLIPSIS));

        *m = (mode_t) k;
        return 0;
}

static int json_dispatch_access_mode(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        mode_t *m = userdata;
        uint64_t k;

        if (json_variant_is_null(variant)) {
                *m = MODE_INVALID;
                return 0;
        }

        if (!json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a number.", strna(name));

        k = json_variant_unsigned(variant);
        if (k > 07777)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                "JSON field '%s' outside of valid range 0%s07777.",
                                strna(name), special_glyph(SPECIAL_GLYPH_ELLIPSIS));

        *m = (mode_t) k;
        return 0;
}

static int json_dispatch_environment(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        _cleanup_strv_free_ char **n = NULL;
        char ***l = userdata;
        int r;

        if (json_variant_is_null(variant)) {
                *l = strv_free(*l);
                return 0;
        }

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        for (size_t i = 0; i < json_variant_elements(variant); i++) {
                JsonVariant *e;
                const char *a;

                e = json_variant_by_index(variant, i);
                if (!json_variant_is_string(e))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array of strings.", strna(name));

                assert_se(a = json_variant_string(e));

                if (!env_assignment_is_valid(a))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array of environment variables.", strna(name));

                r = strv_env_replace_strdup(&n, a);
                if (r < 0)
                        return json_log_oom(variant, flags);
        }

        return strv_free_and_replace(*l, n);
}

int json_dispatch_user_disposition(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        UserDisposition *disposition = userdata, k;

        if (json_variant_is_null(variant)) {
                *disposition = _USER_DISPOSITION_INVALID;
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        k = user_disposition_from_string(json_variant_string(variant));
        if (k < 0)
                return json_log(variant, flags, k, "Disposition type '%s' not known.", json_variant_string(variant));

        *disposition = k;
        return 0;
}

static int json_dispatch_storage(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        UserStorage *storage = userdata, k;

        if (json_variant_is_null(variant)) {
                *storage = _USER_STORAGE_INVALID;
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        k = user_storage_from_string(json_variant_string(variant));
        if (k < 0)
                return json_log(variant, flags, k, "Storage type '%s' not known.", json_variant_string(variant));

        *storage = k;
        return 0;
}

static int json_dispatch_tasks_or_memory_max(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        uint64_t *limit = userdata, k;

        if (json_variant_is_null(variant)) {
                *limit = UINT64_MAX;
                return 0;
        }

        if (!json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        k = json_variant_unsigned(variant);
        if (k <= 0 || k >= UINT64_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE),
                                "JSON field '%s' is not in valid range %" PRIu64 "%s%" PRIu64 ".",
                                strna(name), (uint64_t) 1, special_glyph(SPECIAL_GLYPH_ELLIPSIS), UINT64_MAX-1);

        *limit = k;
        return 0;
}

static int json_dispatch_weight(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        uint64_t *weight = userdata, k;

        if (json_variant_is_null(variant)) {
                *weight = UINT64_MAX;
                return 0;
        }

        if (!json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        k = json_variant_unsigned(variant);
        if (k <= CGROUP_WEIGHT_MIN || k >= CGROUP_WEIGHT_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE),
                                "JSON field '%s' is not in valid range %" PRIu64 "%s%" PRIu64 ".",
                                strna(name), (uint64_t) CGROUP_WEIGHT_MIN,
                                special_glyph(SPECIAL_GLYPH_ELLIPSIS), (uint64_t) CGROUP_WEIGHT_MAX);

        *weight = k;
        return 0;
}

int json_dispatch_user_group_list(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        char ***list = userdata;
        JsonVariant *e;
        int r;

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array of strings.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {

                if (!json_variant_is_string(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not a string.");

                if (!valid_user_group_name(json_variant_string(e), FLAGS_SET(flags, JSON_RELAX) ? VALID_USER_RELAX : 0))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not a valid user/group name: %s", json_variant_string(e));

                r = strv_extend(&l, json_variant_string(e));
                if (r < 0)
                        return json_log(e, flags, r, "Failed to append array element: %m");
        }

        r = strv_extend_strv(list, l, true);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to merge user/group arrays: %m");

        return 0;
}

static int dispatch_secret(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch secret_dispatch_table[] = {
                { "password",                                   _JSON_VARIANT_TYPE_INVALID, json_dispatch_strv,     offsetof(UserRecord, password),                                       0 },
                { "tokenPin",                                   _JSON_VARIANT_TYPE_INVALID, json_dispatch_strv,     offsetof(UserRecord, token_pin),                                      0 },
                { "pkcs11Pin",   /* legacy alias */             _JSON_VARIANT_TYPE_INVALID, json_dispatch_strv,     offsetof(UserRecord, token_pin),                                      0 },
                { "pkcs11ProtectedAuthenticationPathPermitted", JSON_VARIANT_BOOLEAN,       json_dispatch_tristate, offsetof(UserRecord, pkcs11_protected_authentication_path_permitted), 0 },
                { "fido2UserPresencePermitted",                 JSON_VARIANT_BOOLEAN,       json_dispatch_tristate, offsetof(UserRecord, fido2_user_presence_permitted),                  0 },
                { "fido2UserVerificationPermitted",             JSON_VARIANT_BOOLEAN,       json_dispatch_tristate, offsetof(UserRecord, fido2_user_verification_permitted),              0 },
                {},
        };

        return json_dispatch(variant, secret_dispatch_table, flags, userdata);
}

static int dispatch_pkcs11_uri(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        char **s = userdata;
        const char *n;
        int r;

        if (json_variant_is_null(variant)) {
                *s = mfree(*s);
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        n = json_variant_string(variant);
        if (!pkcs11_uri_valid(n))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid RFC7512 PKCS#11 URI.", strna(name));

        r = free_and_strdup(s, n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

static int dispatch_pkcs11_uri_array(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        _cleanup_strv_free_ char **z = NULL;
        char ***l = userdata;
        JsonVariant *e;
        int r;

        if (json_variant_is_null(variant)) {
                *l = strv_free(*l);
                return 0;
        }

        if (json_variant_is_string(variant)) {
                const char *n;

                n = json_variant_string(variant);
                if (!pkcs11_uri_valid(n))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid RFC7512 PKCS#11 URI.", strna(name));

                z = strv_new(n);
                if (!z)
                        return log_oom();

        } else {

                if (!json_variant_is_array(variant))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string or array of strings.", strna(name));

                JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                        const char *n;

                        if (!json_variant_is_string(e))
                                return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not a string.");

                        n = json_variant_string(e);
                        if (!pkcs11_uri_valid(n))
                                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element in '%s' is not a valid RFC7512 PKCS#11 URI: %s", strna(name), n);

                        r = strv_extend(&z, n);
                        if (r < 0)
                                return log_oom();
                }
        }

        strv_free_and_replace(*l, z);
        return 0;
}

static int dispatch_pkcs11_key_data(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        Pkcs11EncryptedKey *k = userdata;
        size_t l;
        void *b;
        int r;

        if (json_variant_is_null(variant)) {
                k->data = erase_and_free(k->data);
                k->size = 0;
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        r = unbase64mem(json_variant_string(variant), SIZE_MAX, &b, &l);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to decode encrypted PKCS#11 key: %m");

        erase_and_free(k->data);
        k->data = b;
        k->size = l;

        return 0;
}

static int dispatch_pkcs11_key(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        UserRecord *h = userdata;
        JsonVariant *e;
        int r;

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array of objects.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                Pkcs11EncryptedKey *array, *k;

                static const JsonDispatch pkcs11_key_dispatch_table[] = {
                        { "uri",            JSON_VARIANT_STRING, dispatch_pkcs11_uri,      offsetof(Pkcs11EncryptedKey, uri),             JSON_MANDATORY },
                        { "data",           JSON_VARIANT_STRING, dispatch_pkcs11_key_data, 0,                                             JSON_MANDATORY },
                        { "hashedPassword", JSON_VARIANT_STRING, json_dispatch_string,     offsetof(Pkcs11EncryptedKey, hashed_password), JSON_MANDATORY },
                        {},
                };

                if (!json_variant_is_object(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not an object.");

                array = reallocarray(h->pkcs11_encrypted_key, h->n_pkcs11_encrypted_key + 1, sizeof(Pkcs11EncryptedKey));
                if (!array)
                        return log_oom();

                h->pkcs11_encrypted_key = array;
                k = h->pkcs11_encrypted_key + h->n_pkcs11_encrypted_key;
                *k = (Pkcs11EncryptedKey) {};

                r = json_dispatch(e, pkcs11_key_dispatch_table, flags, k);
                if (r < 0) {
                        pkcs11_encrypted_key_done(k);
                        return r;
                }

                h->n_pkcs11_encrypted_key++;
        }

        return 0;
}

static int dispatch_fido2_hmac_credential(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        Fido2HmacCredential *k = userdata;
        size_t l;
        void *b;
        int r;

        if (json_variant_is_null(variant)) {
                k->id = mfree(k->id);
                k->size = 0;
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        r = unbase64mem(json_variant_string(variant), SIZE_MAX, &b, &l);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to decode FIDO2 credential ID: %m");

        free_and_replace(k->id, b);
        k->size = l;

        return 0;
}

static int dispatch_fido2_hmac_credential_array(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        UserRecord *h = userdata;
        JsonVariant *e;
        int r;

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array of strings.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                Fido2HmacCredential *array;
                size_t l;
                void *b;

                if (!json_variant_is_string(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not a string.");

                array = reallocarray(h->fido2_hmac_credential, h->n_fido2_hmac_credential + 1, sizeof(Fido2HmacCredential));
                if (!array)
                        return log_oom();

                r = unbase64mem(json_variant_string(e), SIZE_MAX, &b, &l);
                if (r < 0)
                        return json_log(variant, flags, r, "Failed to decode FIDO2 credential ID: %m");

                h->fido2_hmac_credential = array;

                h->fido2_hmac_credential[h->n_fido2_hmac_credential++] = (Fido2HmacCredential) {
                        .id = b,
                        .size = l,
                };
        }

        return 0;
}

static int dispatch_fido2_hmac_salt_value(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        Fido2HmacSalt *k = userdata;
        size_t l;
        void *b;
        int r;

        if (json_variant_is_null(variant)) {
                k->salt = erase_and_free(k->salt);
                k->salt_size = 0;
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        r = unbase64mem(json_variant_string(variant), SIZE_MAX, &b, &l);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to decode FIDO2 salt: %m");

        erase_and_free(k->salt);
        k->salt = b;
        k->salt_size = l;

        return 0;
}

static int dispatch_fido2_hmac_salt(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        UserRecord *h = userdata;
        JsonVariant *e;
        int r;

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array of objects.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                Fido2HmacSalt *array, *k;

                static const JsonDispatch fido2_hmac_salt_dispatch_table[] = {
                        { "credential",     JSON_VARIANT_STRING,  dispatch_fido2_hmac_credential, offsetof(Fido2HmacSalt, credential),      JSON_MANDATORY },
                        { "salt",           JSON_VARIANT_STRING,  dispatch_fido2_hmac_salt_value, 0,                                        JSON_MANDATORY },
                        { "hashedPassword", JSON_VARIANT_STRING,  json_dispatch_string,           offsetof(Fido2HmacSalt, hashed_password), JSON_MANDATORY },
                        { "up",             JSON_VARIANT_BOOLEAN, json_dispatch_tristate,         offsetof(Fido2HmacSalt, up),              0              },
                        { "uv",             JSON_VARIANT_BOOLEAN, json_dispatch_tristate,         offsetof(Fido2HmacSalt, uv),              0              },
                        { "clientPin",      JSON_VARIANT_BOOLEAN, json_dispatch_tristate,         offsetof(Fido2HmacSalt, client_pin),      0              },
                        {},
                };

                if (!json_variant_is_object(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not an object.");

                array = reallocarray(h->fido2_hmac_salt, h->n_fido2_hmac_salt + 1, sizeof(Fido2HmacSalt));
                if (!array)
                        return log_oom();

                h->fido2_hmac_salt = array;
                k = h->fido2_hmac_salt + h->n_fido2_hmac_salt;
                *k = (Fido2HmacSalt) {
                        .uv = -1,
                        .up = -1,
                        .client_pin = -1,
                };

                r = json_dispatch(e, fido2_hmac_salt_dispatch_table, flags, k);
                if (r < 0) {
                        fido2_hmac_salt_done(k);
                        return r;
                }

                h->n_fido2_hmac_salt++;
        }

        return 0;
}

static int dispatch_recovery_key(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        UserRecord *h = userdata;
        JsonVariant *e;
        int r;

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array of objects.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                RecoveryKey *array, *k;

                static const JsonDispatch recovery_key_dispatch_table[] = {
                        { "type",           JSON_VARIANT_STRING, json_dispatch_string, 0,                                      JSON_MANDATORY },
                        { "hashedPassword", JSON_VARIANT_STRING, json_dispatch_string, offsetof(RecoveryKey, hashed_password), JSON_MANDATORY },
                        {},
                };

                if (!json_variant_is_object(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not an object.");

                array = reallocarray(h->recovery_key, h->n_recovery_key + 1, sizeof(RecoveryKey));
                if (!array)
                        return log_oom();

                h->recovery_key = array;
                k = h->recovery_key + h->n_recovery_key;
                *k = (RecoveryKey) {};

                r = json_dispatch(e, recovery_key_dispatch_table, flags, k);
                if (r < 0) {
                        recovery_key_done(k);
                        return r;
                }

                h->n_recovery_key++;
        }

        return 0;
}

static int dispatch_auto_resize_mode(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        AutoResizeMode *mode = userdata, m;

        assert_se(mode);

        if (json_variant_is_null(variant)) {
                *mode = _AUTO_RESIZE_MODE_INVALID;
                return 0;
        }

        if (json_variant_is_boolean(variant)) {
                *mode = json_variant_boolean(variant) ? AUTO_RESIZE_SHRINK_AND_GROW : AUTO_RESIZE_OFF;
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string, boolean or null.", strna(name));

        m = auto_resize_mode_from_string(json_variant_string(variant));
        if (m < 0)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid automatic resize mode.", strna(name));

        *mode = m;
        return 0;
}

static int dispatch_rebalance_weight(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        uint64_t *rebalance_weight = userdata;
        uintmax_t u;

        assert_se(rebalance_weight);

        if (json_variant_is_null(variant)) {
                *rebalance_weight = REBALANCE_WEIGHT_UNSET;
                return 0;
        }

        if (json_variant_is_boolean(variant)) {
                *rebalance_weight = json_variant_boolean(variant) ? REBALANCE_WEIGHT_DEFAULT : REBALANCE_WEIGHT_OFF;
                return 0;
        }

        if (!json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an unsigned integer, boolean or null.", strna(name));

        u = json_variant_unsigned(variant);
        if (u >= REBALANCE_WEIGHT_MIN && u <= REBALANCE_WEIGHT_MAX)
                *rebalance_weight = (uint64_t) u;
        else if (u == 0)
                *rebalance_weight = REBALANCE_WEIGHT_OFF;
        else
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE),
                                "Rebalance weight is out of valid range %" PRIu64 "%s%" PRIu64 ".",
                                REBALANCE_WEIGHT_MIN, special_glyph(SPECIAL_GLYPH_ELLIPSIS), REBALANCE_WEIGHT_MAX);

        return 0;
}

static int dispatch_privileged(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch privileged_dispatch_table[] = {
                { "passwordHint",       JSON_VARIANT_STRING,        json_dispatch_string,     offsetof(UserRecord, password_hint),        0         },
                { "hashedPassword",     _JSON_VARIANT_TYPE_INVALID, json_dispatch_strv,       offsetof(UserRecord, hashed_password),      JSON_SAFE },
                { "sshAuthorizedKeys",  _JSON_VARIANT_TYPE_INVALID, json_dispatch_strv,       offsetof(UserRecord, ssh_authorized_keys),  0         },
                { "pkcs11EncryptedKey", JSON_VARIANT_ARRAY,         dispatch_pkcs11_key,      0,                                          0         },
                { "fido2HmacSalt",      JSON_VARIANT_ARRAY,         dispatch_fido2_hmac_salt, 0,                                          0         },
                { "recoveryKey",        JSON_VARIANT_ARRAY,         dispatch_recovery_key,    0,                                          0         },
                {},
        };

        return json_dispatch(variant, privileged_dispatch_table, flags, userdata);
}

static int dispatch_binding(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch binding_dispatch_table[] = {
                { "imagePath",         JSON_VARIANT_STRING,        json_dispatch_image_path,     offsetof(UserRecord, image_path),           0         },
                { "homeDirectory",     JSON_VARIANT_STRING,        json_dispatch_home_directory, offsetof(UserRecord, home_directory),       0         },
                { "partitionUuid",     JSON_VARIANT_STRING,        json_dispatch_id128,          offsetof(UserRecord, partition_uuid),       0         },
                { "luksUuid",          JSON_VARIANT_STRING,        json_dispatch_id128,          offsetof(UserRecord, luks_uuid),            0         },
                { "fileSystemUuid",    JSON_VARIANT_STRING,        json_dispatch_id128,          offsetof(UserRecord, file_system_uuid),     0         },
                { "uid",               JSON_VARIANT_UNSIGNED,      json_dispatch_uid_gid,        offsetof(UserRecord, uid),                  0         },
                { "gid",               JSON_VARIANT_UNSIGNED,      json_dispatch_uid_gid,        offsetof(UserRecord, gid),                  0         },
                { "storage",           JSON_VARIANT_STRING,        json_dispatch_storage,        offsetof(UserRecord, storage),              0         },
                { "fileSystemType",    JSON_VARIANT_STRING,        json_dispatch_string,         offsetof(UserRecord, file_system_type),     JSON_SAFE },
                { "luksCipher",        JSON_VARIANT_STRING,        json_dispatch_string,         offsetof(UserRecord, luks_cipher),          JSON_SAFE },
                { "luksCipherMode",    JSON_VARIANT_STRING,        json_dispatch_string,         offsetof(UserRecord, luks_cipher_mode),     JSON_SAFE },
                { "luksVolumeKeySize", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,         offsetof(UserRecord, luks_volume_key_size), 0         },
                {},
        };

        JsonVariant *m;
        sd_id128_t mid;
        int r;

        if (!variant)
                return 0;

        if (!json_variant_is_object(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an object.", strna(name));

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to determine machine ID: %m");

        m = json_variant_by_key(variant, SD_ID128_TO_STRING(mid));
        if (!m)
                return 0;

        return json_dispatch(m, binding_dispatch_table, flags, userdata);
}

int per_machine_id_match(JsonVariant *ids, JsonDispatchFlags flags) {
        sd_id128_t mid;
        int r;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return json_log(ids, flags, r, "Failed to acquire machine ID: %m");

        if (json_variant_is_string(ids)) {
                sd_id128_t k;

                r = sd_id128_from_string(json_variant_string(ids), &k);
                if (r < 0) {
                        json_log(ids, flags, r, "%s is not a valid machine ID, ignoring: %m", json_variant_string(ids));
                        return 0;
                }

                return sd_id128_equal(mid, k);
        }

        if (json_variant_is_array(ids)) {
                JsonVariant *e;

                JSON_VARIANT_ARRAY_FOREACH(e, ids) {
                        sd_id128_t k;

                        if (!json_variant_is_string(e)) {
                                json_log(e, flags, 0, "Machine ID is not a string, ignoring: %m");
                                continue;
                        }

                        r = sd_id128_from_string(json_variant_string(e), &k);
                        if (r < 0) {
                                json_log(e, flags, r, "%s is not a valid machine ID, ignoring: %m", json_variant_string(e));
                                continue;
                        }

                        if (sd_id128_equal(mid, k))
                                return true;
                }

                return false;
        }

        json_log(ids, flags, 0, "Machine ID is not a string or array of strings, ignoring: %m");
        return false;
}

int per_machine_hostname_match(JsonVariant *hns, JsonDispatchFlags flags) {
        _cleanup_free_ char *hn = NULL;
        int r;

        r = gethostname_strict(&hn);
        if (r == -ENXIO) {
                json_log(hns, flags, r, "No hostname set, not matching perMachine hostname record: %m");
                return false;
        }
        if (r < 0)
                return json_log(hns, flags, r, "Failed to acquire hostname: %m");

        if (json_variant_is_string(hns))
                return streq(json_variant_string(hns), hn);

        if (json_variant_is_array(hns)) {
                JsonVariant *e;

                JSON_VARIANT_ARRAY_FOREACH(e, hns) {

                        if (!json_variant_is_string(e)) {
                                json_log(e, flags, 0, "Hostname is not a string, ignoring: %m");
                                continue;
                        }

                        if (streq(json_variant_string(hns), hn))
                                return true;
                }

                return false;
        }

        json_log(hns, flags, 0, "Hostname is not a string or array of strings, ignoring: %m");
        return false;
}

static int dispatch_per_machine(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch per_machine_dispatch_table[] = {
                { "matchMachineId",             _JSON_VARIANT_TYPE_INVALID, NULL,                                 0,                                                   0         },
                { "matchHostname",              _JSON_VARIANT_TYPE_INVALID, NULL,                                 0,                                                   0         },
                { "iconName",                   JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, icon_name),                     JSON_SAFE },
                { "avatarPath",                 JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, avatar_path),                   JSON_SAFE },
                { "location",                   JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, location),                      0         },
                { "shell",                      JSON_VARIANT_STRING,        json_dispatch_filename_or_path,       offsetof(UserRecord, shell),                         0         },
                { "umask",                      JSON_VARIANT_UNSIGNED,      json_dispatch_umask,                  offsetof(UserRecord, umask),                         0         },
                { "environment",                JSON_VARIANT_ARRAY,         json_dispatch_environment,            offsetof(UserRecord, environment),                   0         },
                { "timeZone",                   JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, time_zone),                     JSON_SAFE },
                { "preferredLanguage",          JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, preferred_language),            JSON_SAFE },
                { "niceLevel",                  _JSON_VARIANT_TYPE_INVALID, json_dispatch_nice,                   offsetof(UserRecord, nice_level),                    0         },
                { "resourceLimits",             _JSON_VARIANT_TYPE_INVALID, json_dispatch_rlimits,                offsetof(UserRecord, rlimits),                       0         },
                { "locked",                     JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, locked),                        0         },
                { "notBeforeUSec",              _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, not_before_usec),               0         },
                { "notAfterUSec",               _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, not_after_usec),                0         },
                { "storage",                    JSON_VARIANT_STRING,        json_dispatch_storage,                offsetof(UserRecord, storage),                       0         },
                { "diskSize",                   _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, disk_size),                     0         },
                { "diskSizeRelative",           _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, disk_size_relative),            0         },
                { "skeletonDirectory",          JSON_VARIANT_STRING,        json_dispatch_path,                   offsetof(UserRecord, skeleton_directory),            0         },
                { "accessMode",                 JSON_VARIANT_UNSIGNED,      json_dispatch_access_mode,            offsetof(UserRecord, access_mode),                   0         },
                { "tasksMax",                   JSON_VARIANT_UNSIGNED,      json_dispatch_tasks_or_memory_max,    offsetof(UserRecord, tasks_max),                     0         },
                { "memoryHigh",                 JSON_VARIANT_UNSIGNED,      json_dispatch_tasks_or_memory_max,    offsetof(UserRecord, memory_high),                   0         },
                { "memoryMax",                  JSON_VARIANT_UNSIGNED,      json_dispatch_tasks_or_memory_max,    offsetof(UserRecord, memory_max),                    0         },
                { "cpuWeight",                  JSON_VARIANT_UNSIGNED,      json_dispatch_weight,                 offsetof(UserRecord, cpu_weight),                    0         },
                { "ioWeight",                   JSON_VARIANT_UNSIGNED,      json_dispatch_weight,                 offsetof(UserRecord, io_weight),                     0         },
                { "mountNoDevices",             JSON_VARIANT_BOOLEAN,       json_dispatch_boolean,                offsetof(UserRecord, nodev),                         0         },
                { "mountNoSuid",                JSON_VARIANT_BOOLEAN,       json_dispatch_boolean,                offsetof(UserRecord, nosuid),                        0         },
                { "mountNoExecute",             JSON_VARIANT_BOOLEAN,       json_dispatch_boolean,                offsetof(UserRecord, noexec),                        0         },
                { "cifsDomain",                 JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, cifs_domain),                   JSON_SAFE },
                { "cifsUserName",               JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, cifs_user_name),                JSON_SAFE },
                { "cifsService",                JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, cifs_service),                  JSON_SAFE },
                { "cifsExtraMountOptions",      JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, cifs_extra_mount_options),      0         },
                { "imagePath",                  JSON_VARIANT_STRING,        json_dispatch_path,                   offsetof(UserRecord, image_path),                    0         },
                { "uid",                        JSON_VARIANT_UNSIGNED,      json_dispatch_uid_gid,                offsetof(UserRecord, uid),                           0         },
                { "gid",                        JSON_VARIANT_UNSIGNED,      json_dispatch_uid_gid,                offsetof(UserRecord, gid),                           0         },
                { "memberOf",                   JSON_VARIANT_ARRAY,         json_dispatch_user_group_list,        offsetof(UserRecord, member_of),                     JSON_RELAX},
                { "capabilityBoundingSet",      JSON_VARIANT_ARRAY,         json_dispatch_strv,                   offsetof(UserRecord, capability_bounding_set),       JSON_SAFE },
                { "capabilityAmbientSet",       JSON_VARIANT_ARRAY,         json_dispatch_strv,                   offsetof(UserRecord, capability_ambient_set),        JSON_SAFE },
                { "fileSystemType",             JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, file_system_type),              JSON_SAFE },
                { "partitionUuid",              JSON_VARIANT_STRING,        json_dispatch_id128,                  offsetof(UserRecord, partition_uuid),                0         },
                { "luksUuid",                   JSON_VARIANT_STRING,        json_dispatch_id128,                  offsetof(UserRecord, luks_uuid),                     0         },
                { "fileSystemUuid",             JSON_VARIANT_STRING,        json_dispatch_id128,                  offsetof(UserRecord, file_system_uuid),              0         },
                { "luksDiscard",                _JSON_VARIANT_TYPE_INVALID, json_dispatch_tristate,               offsetof(UserRecord, luks_discard),                  0,        },
                { "luksOfflineDiscard",         _JSON_VARIANT_TYPE_INVALID, json_dispatch_tristate,               offsetof(UserRecord, luks_offline_discard),          0,        },
                { "luksCipher",                 JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_cipher),                   JSON_SAFE },
                { "luksCipherMode",             JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_cipher_mode),              JSON_SAFE },
                { "luksVolumeKeySize",          _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_volume_key_size),          0         },
                { "luksPbkdfHashAlgorithm",     JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_pbkdf_hash_algorithm),     JSON_SAFE },
                { "luksPbkdfType",              JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_pbkdf_type),               JSON_SAFE },
                { "luksPbkdfForceIterations",   _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_pbkdf_force_iterations),   0         },
                { "luksPbkdfTimeCostUSec",      _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_pbkdf_time_cost_usec),     0         },
                { "luksPbkdfMemoryCost",        _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_pbkdf_memory_cost),        0         },
                { "luksPbkdfParallelThreads",   _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_pbkdf_parallel_threads),   0         },
                { "luksSectorSize",             _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_sector_size),              0         },
                { "luksExtraMountOptions",      JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_extra_mount_options),      0         },
                { "dropCaches",                 JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, drop_caches),                   0         },
                { "autoResizeMode",             _JSON_VARIANT_TYPE_INVALID, dispatch_auto_resize_mode,            offsetof(UserRecord, auto_resize_mode),              0         },
                { "rebalanceWeight",            _JSON_VARIANT_TYPE_INVALID, dispatch_rebalance_weight,            offsetof(UserRecord, rebalance_weight),              0         },
                { "rateLimitIntervalUSec",      _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, ratelimit_interval_usec),       0         },
                { "rateLimitBurst",             _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, ratelimit_burst),               0         },
                { "enforcePasswordPolicy",      JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, enforce_password_policy),       0         },
                { "autoLogin",                  JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, auto_login),                    0         },
                { "stopDelayUSec",              _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, stop_delay_usec),               0         },
                { "killProcesses",              JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, kill_processes),                0         },
                { "passwordChangeMinUSec",      _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, password_change_min_usec),      0         },
                { "passwordChangeMaxUSec",      _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, password_change_max_usec),      0         },
                { "passwordChangeWarnUSec",     _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, password_change_warn_usec),     0         },
                { "passwordChangeInactiveUSec", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, password_change_inactive_usec), 0         },
                { "passwordChangeNow",          JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, password_change_now),           0         },
                { "pkcs11TokenUri",             JSON_VARIANT_ARRAY,         dispatch_pkcs11_uri_array,            offsetof(UserRecord, pkcs11_token_uri),              0         },
                { "fido2HmacCredential",        JSON_VARIANT_ARRAY,         dispatch_fido2_hmac_credential_array, 0,                                                   0         },
                {},
        };

        JsonVariant *e;
        int r;

        if (!variant)
                return 0;

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                bool matching = false;
                JsonVariant *m;

                if (!json_variant_is_object(e))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array of objects.", strna(name));

                m = json_variant_by_key(e, "matchMachineId");
                if (m) {
                        r = per_machine_id_match(m, flags);
                        if (r < 0)
                                return r;

                        matching = r > 0;
                }

                if (!matching) {
                        m = json_variant_by_key(e, "matchHostname");
                        if (m) {
                                r = per_machine_hostname_match(m, flags);
                                if (r < 0)
                                        return r;

                                matching = r > 0;
                        }
                }

                if (!matching)
                        continue;

                r = json_dispatch(e, per_machine_dispatch_table, flags, userdata);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dispatch_status(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch status_dispatch_table[] = {
                { "diskUsage",                  _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, disk_usage),                    0         },
                { "diskFree",                   _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, disk_free),                     0         },
                { "diskSize",                   _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, disk_size),                     0         },
                { "diskCeiling",                _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, disk_ceiling),                  0         },
                { "diskFloor",                  _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, disk_floor),                    0         },
                { "state",                      JSON_VARIANT_STRING,        json_dispatch_string,      offsetof(UserRecord, state),                         JSON_SAFE },
                { "service",                    JSON_VARIANT_STRING,        json_dispatch_string,      offsetof(UserRecord, service),                       JSON_SAFE },
                { "signedLocally",              _JSON_VARIANT_TYPE_INVALID, json_dispatch_tristate,    offsetof(UserRecord, signed_locally),                0         },
                { "goodAuthenticationCounter",  _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, good_authentication_counter),   0         },
                { "badAuthenticationCounter",   _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, bad_authentication_counter),    0         },
                { "lastGoodAuthenticationUSec", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, last_good_authentication_usec), 0         },
                { "lastBadAuthenticationUSec",  _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, last_bad_authentication_usec),  0         },
                { "rateLimitBeginUSec",         _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, ratelimit_begin_usec),          0         },
                { "rateLimitCount",             _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,      offsetof(UserRecord, ratelimit_count),               0         },
                { "removable",                  JSON_VARIANT_BOOLEAN,       json_dispatch_boolean,     offsetof(UserRecord, removable),                     0         },
                { "accessMode",                 JSON_VARIANT_UNSIGNED,      json_dispatch_access_mode, offsetof(UserRecord, access_mode),                   0         },
                { "fileSystemType",             JSON_VARIANT_STRING,        json_dispatch_string,      offsetof(UserRecord, file_system_type),              JSON_SAFE },
                {},
        };

        JsonVariant *m;
        sd_id128_t mid;
        int r;

        if (!variant)
                return 0;

        if (!json_variant_is_object(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an object.", strna(name));

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to determine machine ID: %m");

        m = json_variant_by_key(variant, SD_ID128_TO_STRING(mid));
        if (!m)
                return 0;

        return json_dispatch(m, status_dispatch_table, flags, userdata);
}

int user_record_build_image_path(UserStorage storage, const char *user_name_and_realm, char **ret) {
        const char *suffix;
        char *z;

        assert(storage >= 0);
        assert(user_name_and_realm);
        assert(ret);

        if (storage == USER_LUKS)
                suffix = ".home";
        else if (IN_SET(storage, USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT))
                suffix = ".homedir";
        else {
                *ret = NULL;
                return 0;
        }

        z = strjoin(get_home_root(), "/", user_name_and_realm, suffix);
        if (!z)
                return -ENOMEM;

        *ret = path_simplify(z);
        return 1;
}

static int user_record_augment(UserRecord *h, JsonDispatchFlags json_flags) {
        int r;

        assert(h);

        if (!FLAGS_SET(h->mask, USER_RECORD_REGULAR))
                return 0;

        assert(h->user_name);

        if (!h->user_name_and_realm_auto && h->realm) {
                h->user_name_and_realm_auto = strjoin(h->user_name, "@", h->realm);
                if (!h->user_name_and_realm_auto)
                        return json_log_oom(h->json, json_flags);
        }

        /* Let's add in the following automatisms only for regular users, they don't make sense for any others */
        if (user_record_disposition(h) != USER_REGULAR)
                return 0;

        if (!h->home_directory && !h->home_directory_auto) {
                h->home_directory_auto = path_join(get_home_root(), h->user_name);
                if (!h->home_directory_auto)
                        return json_log_oom(h->json, json_flags);
        }

        if (!h->image_path && !h->image_path_auto) {
                r = user_record_build_image_path(user_record_storage(h), user_record_user_name_and_realm(h), &h->image_path_auto);
                if (r < 0)
                        return json_log(h->json, json_flags, r, "Failed to determine default image path: %m");
        }

        return 0;
}

int user_group_record_mangle(
                JsonVariant *v,
                UserRecordLoadFlags load_flags,
                JsonVariant **ret_variant,
                UserRecordMask *ret_mask) {

        static const struct {
                UserRecordMask mask;
                const char *name;
        } mask_field[] = {
                { USER_RECORD_PRIVILEGED,  "privileged" },
                { USER_RECORD_SECRET,      "secret"     },
                { USER_RECORD_BINDING,     "binding"    },
                { USER_RECORD_PER_MACHINE, "perMachine" },
                { USER_RECORD_STATUS,      "status"     },
                { USER_RECORD_SIGNATURE,   "signature"  },
        };

        JsonDispatchFlags json_flags = USER_RECORD_LOAD_FLAGS_TO_JSON_DISPATCH_FLAGS(load_flags);
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        JsonVariant *array[ELEMENTSOF(mask_field) * 2];
        size_t n_retain = 0;
        UserRecordMask m = 0;
        int r;

        assert((load_flags & _USER_RECORD_MASK_MAX) == 0); /* detect mistakes when accidentally passing
                                                            * UserRecordMask bit masks as UserRecordLoadFlags
                                                            * value */

        assert(v);
        assert(ret_variant);
        assert(ret_mask);

        /* Note that this function is shared with the group record parser, hence we try to be generic in our
         * log message wording here, to cover both cases. */

        if (!json_variant_is_object(v))
                return json_log(v, json_flags, SYNTHETIC_ERRNO(EBADMSG), "Record is not a JSON object, refusing.");

        if (USER_RECORD_ALLOW_MASK(load_flags) == 0) /* allow nothing? */
                return json_log(v, json_flags, SYNTHETIC_ERRNO(EINVAL), "Nothing allowed in record, refusing.");

        if (USER_RECORD_STRIP_MASK(load_flags) == _USER_RECORD_MASK_MAX) /* strip everything? */
                return json_log(v, json_flags, SYNTHETIC_ERRNO(EINVAL), "Stripping everything from record, refusing.");

        /* Check if we have the special sections and if they match our flags set */
        for (size_t i = 0; i < ELEMENTSOF(mask_field); i++) {
                JsonVariant *e, *k;

                if (FLAGS_SET(USER_RECORD_STRIP_MASK(load_flags), mask_field[i].mask)) {
                        if (!w)
                                w = json_variant_ref(v);

                        r = json_variant_filter(&w, STRV_MAKE(mask_field[i].name));
                        if (r < 0)
                                return json_log(w, json_flags, r, "Failed to remove field from variant: %m");

                        continue;
                }

                e = json_variant_by_key_full(v, mask_field[i].name, &k);
                if (e) {
                        if (!FLAGS_SET(USER_RECORD_ALLOW_MASK(load_flags), mask_field[i].mask))
                                return json_log(e, json_flags, SYNTHETIC_ERRNO(EBADMSG), "Record contains '%s' field, which is not allowed.", mask_field[i].name);

                        if (FLAGS_SET(load_flags, USER_RECORD_STRIP_REGULAR)) {
                                array[n_retain++] = k;
                                array[n_retain++] = e;
                        }

                        m |= mask_field[i].mask;
                } else {
                        if (FLAGS_SET(USER_RECORD_REQUIRE_MASK(load_flags), mask_field[i].mask))
                                return json_log(v, json_flags, SYNTHETIC_ERRNO(EBADMSG), "Record lacks '%s' field, which is required.", mask_field[i].name);
                }
        }

        if (FLAGS_SET(load_flags, USER_RECORD_STRIP_REGULAR)) {
                /* If we are supposed to strip regular items, then let's instead just allocate a new object
                 * with just the stuff we need. */

                w = json_variant_unref(w);
                r = json_variant_new_object(&w, array, n_retain);
                if (r < 0)
                        return json_log(v, json_flags, r, "Failed to allocate new object: %m");
        } else
                /* And now check if there's anything else in the record */
                for (size_t i = 0; i < json_variant_elements(v); i += 2) {
                        const char *f;
                        bool special = false;

                        assert_se(f = json_variant_string(json_variant_by_index(v, i)));

                        for (size_t j = 0; j < ELEMENTSOF(mask_field); j++)
                                if (streq(f, mask_field[j].name)) { /* already covered in the loop above */
                                        special = true;
                                        continue;
                                }

                        if (!special) {
                                if ((load_flags & (USER_RECORD_ALLOW_REGULAR|USER_RECORD_REQUIRE_REGULAR)) == 0)
                                        return json_log(v, json_flags, SYNTHETIC_ERRNO(EBADMSG), "Record contains '%s' field, which is not allowed.", f);

                                m |= USER_RECORD_REGULAR;
                                break;
                        }
                }

        if (FLAGS_SET(load_flags, USER_RECORD_REQUIRE_REGULAR) && !FLAGS_SET(m, USER_RECORD_REGULAR))
                return json_log(v, json_flags, SYNTHETIC_ERRNO(EBADMSG), "Record lacks basic identity fields, which are required.");

        if (!FLAGS_SET(load_flags, USER_RECORD_EMPTY_OK) && m == 0)
                return json_log(v, json_flags, SYNTHETIC_ERRNO(EBADMSG), "Record is empty.");

        if (w)
                *ret_variant = TAKE_PTR(w);
        else
                *ret_variant = json_variant_ref(v);

        *ret_mask = m;
        return 0;
}

int user_record_load(UserRecord *h, JsonVariant *v, UserRecordLoadFlags load_flags) {

        static const JsonDispatch user_dispatch_table[] = {
                { "userName",                   JSON_VARIANT_STRING,        json_dispatch_user_group_name,        offsetof(UserRecord, user_name),                     JSON_RELAX},
                { "realm",                      JSON_VARIANT_STRING,        json_dispatch_realm,                  offsetof(UserRecord, realm),                         0         },
                { "realName",                   JSON_VARIANT_STRING,        json_dispatch_gecos,                  offsetof(UserRecord, real_name),                     0         },
                { "emailAddress",               JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, email_address),                 JSON_SAFE },
                { "iconName",                   JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, icon_name),                     JSON_SAFE },
                { "avatarPath",                 JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, avatar_path),                   JSON_SAFE },
                { "location",                   JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, location),                      0         },
                { "disposition",                JSON_VARIANT_STRING,        json_dispatch_user_disposition,       offsetof(UserRecord, disposition),                   0         },
                { "lastChangeUSec",             _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, last_change_usec),              0         },
                { "lastPasswordChangeUSec",     _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, last_password_change_usec),     0         },
                { "shell",                      JSON_VARIANT_STRING,        json_dispatch_filename_or_path,       offsetof(UserRecord, shell),                         0         },
                { "umask",                      JSON_VARIANT_UNSIGNED,      json_dispatch_umask,                  offsetof(UserRecord, umask),                         0         },
                { "environment",                JSON_VARIANT_ARRAY,         json_dispatch_environment,            offsetof(UserRecord, environment),                   0         },
                { "timeZone",                   JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, time_zone),                     JSON_SAFE },
                { "preferredLanguage",          JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, preferred_language),            JSON_SAFE },
                { "niceLevel",                  _JSON_VARIANT_TYPE_INVALID, json_dispatch_nice,                   offsetof(UserRecord, nice_level),                    0         },
                { "resourceLimits",             _JSON_VARIANT_TYPE_INVALID, json_dispatch_rlimits,                offsetof(UserRecord, rlimits),                       0         },
                { "locked",                     JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, locked),                        0         },
                { "notBeforeUSec",              _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, not_before_usec),               0         },
                { "notAfterUSec",               _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, not_after_usec),                0         },
                { "storage",                    JSON_VARIANT_STRING,        json_dispatch_storage,                offsetof(UserRecord, storage),                       0         },
                { "diskSize",                   _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, disk_size),                     0         },
                { "diskSizeRelative",           _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, disk_size_relative),            0         },
                { "skeletonDirectory",          JSON_VARIANT_STRING,        json_dispatch_path,                   offsetof(UserRecord, skeleton_directory),            0         },
                { "accessMode",                 JSON_VARIANT_UNSIGNED,      json_dispatch_access_mode,            offsetof(UserRecord, access_mode),                   0         },
                { "tasksMax",                   JSON_VARIANT_UNSIGNED,      json_dispatch_tasks_or_memory_max,    offsetof(UserRecord, tasks_max),                     0         },
                { "memoryHigh",                 JSON_VARIANT_UNSIGNED,      json_dispatch_tasks_or_memory_max,    offsetof(UserRecord, memory_high),                   0         },
                { "memoryMax",                  JSON_VARIANT_UNSIGNED,      json_dispatch_tasks_or_memory_max,    offsetof(UserRecord, memory_max),                    0         },
                { "cpuWeight",                  JSON_VARIANT_UNSIGNED,      json_dispatch_weight,                 offsetof(UserRecord, cpu_weight),                    0         },
                { "ioWeight",                   JSON_VARIANT_UNSIGNED,      json_dispatch_weight,                 offsetof(UserRecord, io_weight),                     0         },
                { "mountNoDevices",             JSON_VARIANT_BOOLEAN,       json_dispatch_boolean,                offsetof(UserRecord, nodev),                         0         },
                { "mountNoSuid",                JSON_VARIANT_BOOLEAN,       json_dispatch_boolean,                offsetof(UserRecord, nosuid),                        0         },
                { "mountNoExecute",             JSON_VARIANT_BOOLEAN,       json_dispatch_boolean,                offsetof(UserRecord, noexec),                        0         },
                { "cifsDomain",                 JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, cifs_domain),                   JSON_SAFE },
                { "cifsUserName",               JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, cifs_user_name),                JSON_SAFE },
                { "cifsService",                JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, cifs_service),                  JSON_SAFE },
                { "cifsExtraMountOptions",      JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, cifs_extra_mount_options),      0         },
                { "imagePath",                  JSON_VARIANT_STRING,        json_dispatch_path,                   offsetof(UserRecord, image_path),                    0         },
                { "homeDirectory",              JSON_VARIANT_STRING,        json_dispatch_home_directory,         offsetof(UserRecord, home_directory),                0         },
                { "uid",                        JSON_VARIANT_UNSIGNED,      json_dispatch_uid_gid,                offsetof(UserRecord, uid),                           0         },
                { "gid",                        JSON_VARIANT_UNSIGNED,      json_dispatch_uid_gid,                offsetof(UserRecord, gid),                           0         },
                { "memberOf",                   JSON_VARIANT_ARRAY,         json_dispatch_user_group_list,        offsetof(UserRecord, member_of),                     JSON_RELAX},
                { "capabilityBoundingSet",      JSON_VARIANT_ARRAY,         json_dispatch_strv,                   offsetof(UserRecord, capability_bounding_set),       JSON_SAFE },
                { "capabilityAmbientSet",       JSON_VARIANT_ARRAY,         json_dispatch_strv,                   offsetof(UserRecord, capability_ambient_set),        JSON_SAFE },
                { "fileSystemType",             JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, file_system_type),              JSON_SAFE },
                { "partitionUuid",              JSON_VARIANT_STRING,        json_dispatch_id128,                  offsetof(UserRecord, partition_uuid),                0         },
                { "luksUuid",                   JSON_VARIANT_STRING,        json_dispatch_id128,                  offsetof(UserRecord, luks_uuid),                     0         },
                { "fileSystemUuid",             JSON_VARIANT_STRING,        json_dispatch_id128,                  offsetof(UserRecord, file_system_uuid),              0         },
                { "luksDiscard",                _JSON_VARIANT_TYPE_INVALID, json_dispatch_tristate,               offsetof(UserRecord, luks_discard),                  0         },
                { "luksOfflineDiscard",         _JSON_VARIANT_TYPE_INVALID, json_dispatch_tristate,               offsetof(UserRecord, luks_offline_discard),          0         },
                { "luksCipher",                 JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_cipher),                   JSON_SAFE },
                { "luksCipherMode",             JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_cipher_mode),              JSON_SAFE },
                { "luksVolumeKeySize",          _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_volume_key_size),          0         },
                { "luksPbkdfHashAlgorithm",     JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_pbkdf_hash_algorithm),     JSON_SAFE },
                { "luksPbkdfType",              JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_pbkdf_type),               JSON_SAFE },
                { "luksPbkdfForceIterations",   _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_pbkdf_force_iterations),   0         },
                { "luksPbkdfTimeCostUSec",      _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_pbkdf_time_cost_usec),     0         },
                { "luksPbkdfMemoryCost",        _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_pbkdf_memory_cost),        0         },
                { "luksPbkdfParallelThreads",   _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_pbkdf_parallel_threads),   0         },
                { "luksSectorSize",             _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, luks_sector_size),              0         },
                { "luksExtraMountOptions",      JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, luks_extra_mount_options),      0         },
                { "dropCaches",                 JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, drop_caches),                   0         },
                { "autoResizeMode",             _JSON_VARIANT_TYPE_INVALID, dispatch_auto_resize_mode,            offsetof(UserRecord, auto_resize_mode),              0         },
                { "rebalanceWeight",            _JSON_VARIANT_TYPE_INVALID, dispatch_rebalance_weight,            offsetof(UserRecord, rebalance_weight),              0         },
                { "service",                    JSON_VARIANT_STRING,        json_dispatch_string,                 offsetof(UserRecord, service),                       JSON_SAFE },
                { "rateLimitIntervalUSec",      _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, ratelimit_interval_usec),       0         },
                { "rateLimitBurst",             _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, ratelimit_burst),               0         },
                { "enforcePasswordPolicy",      JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, enforce_password_policy),       0         },
                { "autoLogin",                  JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, auto_login),                    0         },
                { "stopDelayUSec",              _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, stop_delay_usec),               0         },
                { "killProcesses",              JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, kill_processes),                0         },
                { "passwordChangeMinUSec",      _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, password_change_min_usec),      0         },
                { "passwordChangeMaxUSec",      _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, password_change_max_usec),      0         },
                { "passwordChangeWarnUSec",     _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, password_change_warn_usec),     0         },
                { "passwordChangeInactiveUSec", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,                 offsetof(UserRecord, password_change_inactive_usec), 0         },
                { "passwordChangeNow",          JSON_VARIANT_BOOLEAN,       json_dispatch_tristate,               offsetof(UserRecord, password_change_now),           0         },
                { "pkcs11TokenUri",             JSON_VARIANT_ARRAY,         dispatch_pkcs11_uri_array,            offsetof(UserRecord, pkcs11_token_uri),              0         },
                { "fido2HmacCredential",        JSON_VARIANT_ARRAY,         dispatch_fido2_hmac_credential_array, 0,                                                   0         },
                { "recoveryKeyType",            JSON_VARIANT_ARRAY,         json_dispatch_strv,                   offsetof(UserRecord, recovery_key_type),             0         },

                { "secret",                     JSON_VARIANT_OBJECT,        dispatch_secret,                      0,                                                   0         },
                { "privileged",                 JSON_VARIANT_OBJECT,        dispatch_privileged,                  0,                                                   0         },

                /* Ignore the perMachine, binding, status stuff here, and process it later, so that it overrides whatever is set above */
                { "perMachine",                 JSON_VARIANT_ARRAY,         NULL,                                 0,                                                   0         },
                { "binding",                    JSON_VARIANT_OBJECT,        NULL,                                 0,                                                   0         },
                { "status",                     JSON_VARIANT_OBJECT,        NULL,                                 0,                                                   0         },

                /* Ignore 'signature', we check it with explicit accessors instead */
                { "signature",                  JSON_VARIANT_ARRAY,         NULL,                                 0,                                                   0         },
                {},
        };

        JsonDispatchFlags json_flags = USER_RECORD_LOAD_FLAGS_TO_JSON_DISPATCH_FLAGS(load_flags);
        int r;

        assert(h);
        assert(!h->json);

        /* Note that this call will leave a half-initialized record around on failure! */

        r = user_group_record_mangle(v, load_flags, &h->json, &h->mask);
        if (r < 0)
                return r;

        r = json_dispatch(h->json, user_dispatch_table, json_flags, h);
        if (r < 0)
                return r;

        /* During the parsing operation above we ignored the 'perMachine', 'binding' and 'status' fields,
         * since we want them to override the global options. Let's process them now. */

        r = dispatch_per_machine("perMachine", json_variant_by_key(h->json, "perMachine"), json_flags, h);
        if (r < 0)
                return r;

        r = dispatch_binding("binding", json_variant_by_key(h->json, "binding"), json_flags, h);
        if (r < 0)
                return r;

        r = dispatch_status("status", json_variant_by_key(h->json, "status"), json_flags, h);
        if (r < 0)
                return r;

        if (FLAGS_SET(h->mask, USER_RECORD_REGULAR) && !h->user_name)
                return json_log(h->json, json_flags, SYNTHETIC_ERRNO(EINVAL), "User name field missing, refusing.");

        r = user_record_augment(h, json_flags);
        if (r < 0)
                return r;

        return 0;
}

int user_record_build(UserRecord **ret, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *u = NULL;
        va_list ap;
        int r;

        assert(ret);

        va_start(ap, ret);
        r = json_buildv(&v, ap);
        va_end(ap);

        if (r < 0)
                return r;

        u = user_record_new();
        if (!u)
                return -ENOMEM;

        r = user_record_load(u, v, USER_RECORD_LOAD_FULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(u);
        return 0;
}

const char *user_record_user_name_and_realm(UserRecord *h) {
        assert(h);

        /* Return the pre-initialized joined string if it is defined */
        if (h->user_name_and_realm_auto)
                return h->user_name_and_realm_auto;

        /* If it's not defined then we cannot have a realm */
        assert(!h->realm);
        return h->user_name;
}

UserStorage user_record_storage(UserRecord *h) {
        assert(h);

        if (h->storage >= 0)
                return h->storage;

        return USER_CLASSIC;
}

const char *user_record_file_system_type(UserRecord *h) {
        assert(h);

        return h->file_system_type ?: "btrfs";
}

const char *user_record_skeleton_directory(UserRecord *h) {
        assert(h);

        return h->skeleton_directory ?: "/etc/skel";
}

mode_t user_record_access_mode(UserRecord *h) {
        assert(h);

        return h->access_mode != MODE_INVALID ? h->access_mode : 0700;
}

const char* user_record_home_directory(UserRecord *h) {
        assert(h);

        if (h->home_directory)
                return h->home_directory;
        if (h->home_directory_auto)
                return h->home_directory_auto;

        /* The root user is special, hence be special about it */
        if (streq_ptr(h->user_name, "root"))
                return "/root";

        return "/";
}

const char *user_record_image_path(UserRecord *h) {
        assert(h);

        if (h->image_path)
                return h->image_path;
        if (h->image_path_auto)
                return h->image_path_auto;

        return IN_SET(user_record_storage(h), USER_CLASSIC, USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT) ? user_record_home_directory(h) : NULL;
}

const char *user_record_cifs_user_name(UserRecord *h) {
        assert(h);

        return h->cifs_user_name ?: h->user_name;
}

unsigned long user_record_mount_flags(UserRecord *h) {
        assert(h);

        return (h->nosuid ? MS_NOSUID : 0) |
                (h->noexec ? MS_NOEXEC : 0) |
                (h->nodev ? MS_NODEV : 0);
}

const char *user_record_shell(UserRecord *h) {
        assert(h);

        if (h->shell)
                return h->shell;

        if (streq_ptr(h->user_name, "root"))
                return "/bin/sh";

        if (user_record_disposition(h) == USER_REGULAR)
                return DEFAULT_USER_SHELL;

        return NOLOGIN;
}

const char *user_record_real_name(UserRecord *h) {
        assert(h);

        return h->real_name ?: h->user_name;
}

bool user_record_luks_discard(UserRecord *h) {
        const char *ip;

        assert(h);

        if (h->luks_discard >= 0)
                return h->luks_discard;

        ip = user_record_image_path(h);
        if (!ip)
                return false;

        /* Use discard by default if we are referring to a real block device, but not when operating on a
         * loopback device. We want to optimize for SSD and flash storage after all, but we should be careful
         * when storing stuff on top of regular file systems in loopback files as doing discard then would
         * mean thin provisioning and we should not do that willy-nilly since it means we'll risk EIO later
         * on should the disk space to back our file systems not be available. */

        return path_startswith(ip, "/dev/");
}

bool user_record_luks_offline_discard(UserRecord *h) {
        const char *ip;

        assert(h);

        if (h->luks_offline_discard >= 0)
                return h->luks_offline_discard;

        /* Discard while we are logged out should generally be a good idea, except when operating directly on
         * physical media, where we should just bind it to the online discard mode. */

        ip = user_record_image_path(h);
        if (!ip)
                return false;

        if (path_startswith(ip, "/dev/"))
                return user_record_luks_discard(h);

        return true;
}

const char *user_record_luks_cipher(UserRecord *h) {
        assert(h);

        return h->luks_cipher ?: "aes";
}

const char *user_record_luks_cipher_mode(UserRecord *h) {
        assert(h);

        return h->luks_cipher_mode ?: "xts-plain64";
}

uint64_t user_record_luks_volume_key_size(UserRecord *h) {
        assert(h);

        /* We return a value here that can be cast without loss into size_t which is what libcrypsetup expects */

        if (h->luks_volume_key_size == UINT64_MAX)
                return 256 / 8;

        return MIN(h->luks_volume_key_size, SIZE_MAX);
}

const char* user_record_luks_pbkdf_type(UserRecord *h) {
        assert(h);

        return h->luks_pbkdf_type ?: "argon2id";
}

uint64_t user_record_luks_pbkdf_force_iterations(UserRecord *h) {
        assert(h);

        /* propagate default "benchmark" mode as itself */
        if (h->luks_pbkdf_force_iterations == UINT64_MAX)
                return UINT64_MAX;

        /* clamp everything else to actually accepted number of iterations of libcryptsetup */
        return CLAMP(h->luks_pbkdf_force_iterations, 1U, UINT32_MAX);
}

uint64_t user_record_luks_pbkdf_time_cost_usec(UserRecord *h) {
        assert(h);

        /* Returns a value with ms granularity, since that's what libcryptsetup expects */

        if (h->luks_pbkdf_time_cost_usec == UINT64_MAX)
                return 500 * USEC_PER_MSEC; /* We default to 500ms, in contrast to libcryptsetup's 2s, which is just awfully slow on every login */

        return MIN(DIV_ROUND_UP(h->luks_pbkdf_time_cost_usec, USEC_PER_MSEC), UINT32_MAX) * USEC_PER_MSEC;
}

uint64_t user_record_luks_pbkdf_memory_cost(UserRecord *h) {
        assert(h);

        /* Returns a value with kb granularity, since that's what libcryptsetup expects */
        if (h->luks_pbkdf_memory_cost == UINT64_MAX)
                return streq(user_record_luks_pbkdf_type(h), "pbkdf2") ? 0 : /* doesn't apply for simple pbkdf2 */
                        64*1024*1024; /* We default to 64M, since this should work on smaller systems too */

        return MIN(DIV_ROUND_UP(h->luks_pbkdf_memory_cost, 1024), UINT32_MAX) * 1024;
}

uint64_t user_record_luks_pbkdf_parallel_threads(UserRecord *h) {
        assert(h);

        if (h->luks_pbkdf_parallel_threads == UINT64_MAX)
                return streq(user_record_luks_pbkdf_type(h), "pbkdf2") ? 0 : /* doesn't apply for simple pbkdf2 */
                        1; /* We default to 1, since this should work on smaller systems too */

        return MIN(h->luks_pbkdf_parallel_threads, UINT32_MAX);
}

uint64_t user_record_luks_sector_size(UserRecord *h) {
        assert(h);

        if (h->luks_sector_size == UINT64_MAX)
                return 512;

        /* Allow up to 4K due to dm-crypt support and 4K alignment by the homed LUKS backend */
        return CLAMP(UINT64_C(1) << (63 - __builtin_clzl(h->luks_sector_size)), 512U, 4096U);
}

const char *user_record_luks_pbkdf_hash_algorithm(UserRecord *h) {
        assert(h);

        return h->luks_pbkdf_hash_algorithm ?: "sha512";
}

gid_t user_record_gid(UserRecord *h) {
        assert(h);

        if (gid_is_valid(h->gid))
                return h->gid;

        return (gid_t) h->uid;
}

UserDisposition user_record_disposition(UserRecord *h) {
        assert(h);

        if (h->disposition >= 0)
                return h->disposition;

        /* If not declared, derive from UID */

        if (!uid_is_valid(h->uid))
                return _USER_DISPOSITION_INVALID;

        if (h->uid == 0 || h->uid == UID_NOBODY)
                return USER_INTRINSIC;

        if (uid_is_system(h->uid))
                return USER_SYSTEM;

        if (uid_is_dynamic(h->uid))
                return USER_DYNAMIC;

        if (uid_is_container(h->uid))
                return USER_CONTAINER;

        if (h->uid > INT32_MAX)
                return USER_RESERVED;

        return USER_REGULAR;
}

int user_record_removable(UserRecord *h) {
        UserStorage storage;
        assert(h);

        if (h->removable >= 0)
                return h->removable;

        /* Refuse to decide for classic records */
        storage = user_record_storage(h);
        if (h->storage < 0 || h->storage == USER_CLASSIC)
                return -1;

        /* For now consider only LUKS home directories with a reference by path as removable */
        return storage == USER_LUKS && path_startswith(user_record_image_path(h), "/dev/");
}

uint64_t user_record_ratelimit_interval_usec(UserRecord *h) {
        assert(h);

        if (h->ratelimit_interval_usec == UINT64_MAX)
                return DEFAULT_RATELIMIT_INTERVAL_USEC;

        return h->ratelimit_interval_usec;
}

uint64_t user_record_ratelimit_burst(UserRecord *h) {
        assert(h);

        if (h->ratelimit_burst == UINT64_MAX)
                return DEFAULT_RATELIMIT_BURST;

        return h->ratelimit_burst;
}

bool user_record_can_authenticate(UserRecord *h) {
        assert(h);

        /* Returns true if there's some form of property configured that the user can authenticate against */

        if (h->n_pkcs11_encrypted_key > 0)
                return true;

        if (h->n_fido2_hmac_salt > 0)
                return true;

        return !strv_isempty(h->hashed_password);
}

bool user_record_drop_caches(UserRecord *h) {
        assert(h);

        if (h->drop_caches >= 0)
                return h->drop_caches;

        /* By default drop caches on fscrypt, not otherwise. */
        return user_record_storage(h) == USER_FSCRYPT;
}

AutoResizeMode user_record_auto_resize_mode(UserRecord *h) {
        assert(h);

        if (h->auto_resize_mode >= 0)
                return h->auto_resize_mode;

        return user_record_storage(h) == USER_LUKS ? AUTO_RESIZE_SHRINK_AND_GROW : AUTO_RESIZE_OFF;
}

uint64_t user_record_rebalance_weight(UserRecord *h) {
        assert(h);

        if (h->rebalance_weight == REBALANCE_WEIGHT_UNSET)
                return REBALANCE_WEIGHT_DEFAULT;

        return h->rebalance_weight;
}

static uint64_t parse_caps_strv(char **l) {
        uint64_t c = 0;
        int r;

        STRV_FOREACH(i, l) {
                r = capability_from_name(*i);
                if (r < 0)
                        log_debug_errno(r, "Don't know capability '%s', ignoring: %m", *i);
                else
                        c |= UINT64_C(1) << r;
        }

        return c;
}

uint64_t user_record_capability_bounding_set(UserRecord *h) {
        assert(h);

        /* Returns UINT64_MAX if no bounding set is configured (!) */

        if (!h->capability_bounding_set)
                return UINT64_MAX;

        return parse_caps_strv(h->capability_bounding_set);
}

uint64_t user_record_capability_ambient_set(UserRecord *h) {
        assert(h);

        /* Returns UINT64_MAX if no ambient set is configured (!) */

        if (!h->capability_ambient_set)
                return UINT64_MAX;

        return parse_caps_strv(h->capability_ambient_set) & user_record_capability_bounding_set(h);
}

uint64_t user_record_ratelimit_next_try(UserRecord *h) {
        assert(h);

        /* Calculates when the it's possible to login next. Returns:
         *
         * UINT64_MAX → Nothing known
         * 0          → Right away
         * Any other  → Next time in CLOCK_REALTIME in usec (which could be in the past)
         */

        if (h->ratelimit_begin_usec == UINT64_MAX ||
            h->ratelimit_count == UINT64_MAX)
                return UINT64_MAX;

        if (h->ratelimit_begin_usec > now(CLOCK_REALTIME)) /* If the ratelimit time is in the future, then
                                                            * the local clock is probably incorrect. Let's
                                                            * not refuse login then. */
                return UINT64_MAX;

        if (h->ratelimit_count < user_record_ratelimit_burst(h))
                return 0;

        return usec_add(h->ratelimit_begin_usec, user_record_ratelimit_interval_usec(h));
}

bool user_record_equal(UserRecord *a, UserRecord *b) {
        assert(a);
        assert(b);

        /* We assume that when a record is modified its JSON data is updated at the same time, hence it's
         * sufficient to compare the JSON data. */

        return json_variant_equal(a->json, b->json);
}

bool user_record_compatible(UserRecord *a, UserRecord *b) {
        assert(a);
        assert(b);

        /* If either lacks the regular section, we can't really decide, let's hence say they are
         * incompatible. */
        if (!(a->mask & b->mask & USER_RECORD_REGULAR))
                return false;

        return streq_ptr(a->user_name, b->user_name) &&
                streq_ptr(a->realm, b->realm);
}

int user_record_compare_last_change(UserRecord *a, UserRecord *b) {
        assert(a);
        assert(b);

        if (a->last_change_usec == b->last_change_usec)
                return 0;

        /* Always consider a record with a timestamp newer than one without */
        if (a->last_change_usec == UINT64_MAX)
                return -1;
        if (b->last_change_usec == UINT64_MAX)
                return 1;

        return CMP(a->last_change_usec, b->last_change_usec);
}

int user_record_clone(UserRecord *h, UserRecordLoadFlags flags, UserRecord **ret) {
        _cleanup_(user_record_unrefp) UserRecord *c = NULL;
        int r;

        assert(h);
        assert(ret);

        c = user_record_new();
        if (!c)
                return -ENOMEM;

        r = user_record_load(c, h->json, flags);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

int user_record_masked_equal(UserRecord *a, UserRecord *b, UserRecordMask mask) {
        _cleanup_(user_record_unrefp) UserRecord *x = NULL, *y = NULL;
        int r;

        assert(a);
        assert(b);

        /* Compares the two records, but ignores anything not listed in the specified mask */

        if ((a->mask & ~mask) != 0) {
                r = user_record_clone(a, USER_RECORD_ALLOW(mask) | USER_RECORD_STRIP(~mask & _USER_RECORD_MASK_MAX) | USER_RECORD_PERMISSIVE, &x);
                if (r < 0)
                        return r;

                a = x;
        }

        if ((b->mask & ~mask) != 0) {
                r = user_record_clone(b, USER_RECORD_ALLOW(mask) | USER_RECORD_STRIP(~mask & _USER_RECORD_MASK_MAX) | USER_RECORD_PERMISSIVE, &y);
                if (r < 0)
                        return r;

                b = y;
        }

        return user_record_equal(a, b);
}

int user_record_test_blocked(UserRecord *h) {
        usec_t n;

        /* Checks whether access to the specified user shall be allowed at the moment. Returns:
         *
         *          -ESTALE: Record is from the future
         *          -ENOLCK: Record is blocked
         *          -EL2HLT: Record is not valid yet
         *          -EL3HLT: Record is not valid anymore
         *
         */

        assert(h);

        if (h->locked > 0)
                return -ENOLCK;

        n = now(CLOCK_REALTIME);

        if (h->not_before_usec != UINT64_MAX && n < h->not_before_usec)
                return -EL2HLT;
        if (h->not_after_usec != UINT64_MAX && n > h->not_after_usec)
                return -EL3HLT;

        if (h->last_change_usec != UINT64_MAX &&
            h->last_change_usec > n) /* Complain during log-ins when the record is from the future */
                return -ESTALE;

        return 0;
}

int user_record_test_password_change_required(UserRecord *h) {
        bool change_permitted;
        usec_t n;

        assert(h);

        /* Checks whether the user must change the password when logging in

            -EKEYREVOKED: Change password now because admin said so
             -EOWNERDEAD: Change password now because it expired
           -EKEYREJECTED: Password is expired, no changing is allowed
            -EKEYEXPIRED: Password is about to expire, warn user
               -ENETDOWN: Record has expiration info but no password change timestamp
                  -EROFS: No password change required nor permitted
                 -ESTALE: RTC likely incorrect, last password change is in the future
                       0: No password change required, but permitted
         */

        /* If a password change request has been set explicitly, it overrides everything */
        if (h->password_change_now > 0)
                return -EKEYREVOKED;

        n = now(CLOCK_REALTIME);

        /* Password change in the future? Then our RTC is likely incorrect */
        if (h->last_password_change_usec != UINT64_MAX &&
            h->last_password_change_usec > n &&
            (h->password_change_min_usec != UINT64_MAX ||
             h->password_change_max_usec != UINT64_MAX ||
             h->password_change_inactive_usec != UINT64_MAX))
            return -ESTALE;

        /* Then, let's check if password changing is currently allowed at all */
        if (h->password_change_min_usec != UINT64_MAX) {

                /* Expiry configured but no password change timestamp known? */
                if (h->last_password_change_usec == UINT64_MAX)
                        return -ENETDOWN;

                if (h->password_change_min_usec >= UINT64_MAX - h->last_password_change_usec)
                        change_permitted = false;
                else
                        change_permitted = n >= h->last_password_change_usec + h->password_change_min_usec;

        } else
                change_permitted = true;

        /* Let's check whether the password has expired.  */
        if (!(h->password_change_max_usec == UINT64_MAX ||
              h->password_change_max_usec >= UINT64_MAX - h->last_password_change_usec)) {

                uint64_t change_before;

                /* Expiry configured but no password change timestamp known? */
                if (h->last_password_change_usec == UINT64_MAX)
                        return -ENETDOWN;

                /* Password is in inactive phase? */
                if (h->password_change_inactive_usec != UINT64_MAX &&
                    h->password_change_inactive_usec < UINT64_MAX - h->password_change_max_usec) {
                        usec_t added;

                        added = h->password_change_inactive_usec + h->password_change_max_usec;
                        if (added < UINT64_MAX - h->last_password_change_usec &&
                            n >= h->last_password_change_usec + added)
                                return -EKEYREJECTED;
                }

                /* Password needs to be changed now? */
                change_before = h->last_password_change_usec + h->password_change_max_usec;
                if (n >= change_before)
                        return change_permitted ? -EOWNERDEAD : -EKEYREJECTED;

                /* Warn user? */
                if (h->password_change_warn_usec != UINT64_MAX &&
                    (change_before < h->password_change_warn_usec ||
                     n >= change_before - h->password_change_warn_usec))
                        return change_permitted ? -EKEYEXPIRED : -EROFS;
        }

        /* No password changing necessary */
        return change_permitted ? 0 : -EROFS;
}

static const char* const user_storage_table[_USER_STORAGE_MAX] = {
        [USER_CLASSIC]   = "classic",
        [USER_LUKS]      = "luks",
        [USER_DIRECTORY] = "directory",
        [USER_SUBVOLUME] = "subvolume",
        [USER_FSCRYPT]   = "fscrypt",
        [USER_CIFS]      = "cifs",
};

DEFINE_STRING_TABLE_LOOKUP(user_storage, UserStorage);

static const char* const user_disposition_table[_USER_DISPOSITION_MAX] = {
        [USER_INTRINSIC] = "intrinsic",
        [USER_SYSTEM]    = "system",
        [USER_DYNAMIC]   = "dynamic",
        [USER_REGULAR]   = "regular",
        [USER_CONTAINER] = "container",
        [USER_RESERVED]  = "reserved",
};

DEFINE_STRING_TABLE_LOOKUP(user_disposition, UserDisposition);

static const char* const auto_resize_mode_table[_AUTO_RESIZE_MODE_MAX] = {
        [AUTO_RESIZE_OFF]             = "off",
        [AUTO_RESIZE_GROW]            = "grow",
        [AUTO_RESIZE_SHRINK_AND_GROW] = "shrink-and-grow",
};

DEFINE_STRING_TABLE_LOOKUP(auto_resize_mode, AutoResizeMode);
