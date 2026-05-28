/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "alloc-util.h"
#include "bus-polkit.h"
#include "cryptenroll.h"
#include "cryptenroll-list.h"
#include "cryptenroll-varlink.h"
#include "cryptenroll-wipe.h"
#include "cryptsetup-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "json-util.h"
#include "libfido2-util.h"
#include "string-util.h"
#include "varlink-io.systemd.CryptEnroll.h"
#include "varlink-util.h"

int enroll_context_notify_state(const EnrollContext *c, const char *state) {
        int r;

        assert(c);
        assert(state);

        /* Only relevant when invoked over a Varlink connection that asked for progress ('more'). */
        if (!c->link)
                return 0;

        r = sd_varlink_notifybo(c->link, SD_JSON_BUILD_PAIR_STRING("state", state));
        if (r < 0)
                return r;

        return sd_varlink_flush(c->link);
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_enroll_type, EnrollType, enroll_type_from_string);

typedef struct MethodEnrollParameters {
        char *node;
        EnrollType mechanism;
        char *unlock_password;
        char *unlock_keyfile;
        int64_t unlock_keyfile_fd_idx;
        char *unlock_fido2_device;
        char *unlock_tpm2_device;
        char *password;
        char *fido2_device;
        char *fido2_pin;
        int fido2_with_client_pin;
        int fido2_with_user_presence;
        int fido2_with_user_verification;
        sd_json_variant *wipe_slots;
        sd_json_variant *wipe_types;
} MethodEnrollParameters;

static void method_enroll_parameters_done(MethodEnrollParameters *p) {
        assert(p);

        free(p->node);
        erase_and_free(p->unlock_password);
        free(p->unlock_keyfile);
        free(p->unlock_fido2_device);
        free(p->unlock_tpm2_device);
        erase_and_free(p->password);
        free(p->fido2_device);
        erase_and_free(p->fido2_pin);
        sd_json_variant_unref(p->wipe_slots);
        sd_json_variant_unref(p->wipe_types);
}

static int parse_wipe_slots(sd_json_variant *v, EnrollContext *c) {
        sd_json_variant *e;

        assert(c);

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                if (!sd_json_variant_is_unsigned(e))
                        return -EINVAL;

                uint64_t u = sd_json_variant_unsigned(e);
                if (u > INT_MAX)
                        return -ERANGE;

                if (!GREEDY_REALLOC(c->wipe_slots, c->n_wipe_slots + 1))
                        return -ENOMEM;

                c->wipe_slots[c->n_wipe_slots++] = (int) u;
        }

        return 0;
}

static int parse_wipe_types(sd_json_variant *v, EnrollContext *c) {
        sd_json_variant *e;

        assert(c);

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                if (!sd_json_variant_is_string(e))
                        return -EINVAL;

                /* Translate the Varlink (underscore) spelling to the internal (dash) one before lookup. */
                _cleanup_free_ char *s = strdup(sd_json_variant_string(e));
                if (!s)
                        return -ENOMEM;

                EnrollType t = enroll_type_from_string(json_dashify(s));
                if (t < 0)
                        return -EINVAL;

                c->wipe_slots_mask |= 1U << t;
        }

        return 0;
}

static int varlink_error_for_enroll(sd_varlink *link, int error) {
        assert(link);
        assert(error < 0);

        /* Translates the errnos the enrollment/unlock helpers return into the interface's named errors,
         * falling back to a plain errno error. */

        switch (error) {

        case -EHOSTDOWN:        /* check_for_homed() */
                return sd_varlink_error(link, "io.systemd.CryptEnroll.VolumeUnderForeignManagement", NULL);

        case -ENOPKG:           /* credential querying disabled in headless mode but none provided */
                return sd_varlink_error(link, "io.systemd.CryptEnroll.PasswordRequired", NULL);

        case -EPERM:
        case -ENOKEY:           /* provided password/key did not unlock the volume */
                return sd_varlink_error(link, "io.systemd.CryptEnroll.PasswordIncorrect", NULL);

        case -ENODEV:
        case -ENOTUNIQ:         /* no (or no unique) FIDO2 device found */
                return sd_varlink_error(link, "io.systemd.CryptEnroll.FidoDeviceNotFound", NULL);

        case -ENOSTR:           /* FIDO_ERR_ACTION_TIMEOUT */
                return sd_varlink_error(link, "io.systemd.CryptEnroll.FidoActionTimeout", NULL);

        default:
                return sd_varlink_error_errno(link, error);
        }
}

static int vl_method_enroll(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "node",                         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(MethodEnrollParameters, node),                          SD_JSON_MANDATORY },
                { "mechanism",                    SD_JSON_VARIANT_STRING,        json_dispatch_enroll_type, offsetof(MethodEnrollParameters, mechanism),                     SD_JSON_MANDATORY },
                { "unlockPassword",               SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(MethodEnrollParameters, unlock_password),               0 },
                { "unlockKeyFile",                SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(MethodEnrollParameters, unlock_keyfile),                0 },
                { "unlockKeyFileDescriptorIndex", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int64,    offsetof(MethodEnrollParameters, unlock_keyfile_fd_idx),         0 },
                { "unlockFido2Device",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(MethodEnrollParameters, unlock_fido2_device),           0 },
                { "unlockTpm2Device",             SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(MethodEnrollParameters, unlock_tpm2_device),            0 },
                { "password",                     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(MethodEnrollParameters, password),                      0 },
                { "fido2Device",                  SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(MethodEnrollParameters, fido2_device),                  0 },
                { "fido2Pin",                     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(MethodEnrollParameters, fido2_pin),                     0 },
                { "fido2WithClientPin",           SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate, offsetof(MethodEnrollParameters, fido2_with_client_pin),         0 },
                { "fido2WithUserPresence",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate, offsetof(MethodEnrollParameters, fido2_with_user_presence),      0 },
                { "fido2WithUserVerification",    SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate, offsetof(MethodEnrollParameters, fido2_with_user_verification),  0 },
                { "wipeSlots",                    SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant,  offsetof(MethodEnrollParameters, wipe_slots),                    0 },
                { "wipeTypes",                    SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant,  offsetof(MethodEnrollParameters, wipe_types),                    0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        _cleanup_(method_enroll_parameters_done) MethodEnrollParameters p = {
                .mechanism = _ENROLL_TYPE_INVALID,
                .unlock_keyfile_fd_idx = -1,
                .fido2_with_client_pin = -1,
                .fido2_with_user_presence = -1,
                .fido2_with_user_verification = -1,
        };
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(iovec_done_erase) struct iovec vk = {};
        _cleanup_close_ int keyfile_fd = -EBADF;
        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        int slot, r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.mechanism < 0)
                return sd_varlink_error_invalid_parameter_name(link, "mechanism");

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.cryptenroll.enroll",
                        /* details= */ NULL,
                        polkit_registry);
        if (r <= 0)
                return r;

        /* Populate the context. This is the Varlink equivalent of enroll_context_from_args(). */
        _cleanup_(enroll_context_done) EnrollContext c = ENROLL_CONTEXT_NULL;
        c.interactive = false;
        c.enroll_type = p.mechanism;
        c.unlock_type = _UNLOCK_TYPE_INVALID;

        if (strdup_to(&c.node, p.node) < 0)
                return -ENOMEM;

        if (p.unlock_password) {
                if (c.unlock_type >= 0)
                        return sd_varlink_error_invalid_parameter_name(link, "unlockPassword");

                c.unlock_password = TAKE_PTR(p.unlock_password);
                c.unlock_type = UNLOCK_PASSWORD;
        }

        if (p.unlock_keyfile || p.unlock_keyfile_fd_idx >= 0) {
                if (c.unlock_type >= 0)
                        return sd_varlink_error_invalid_parameter_name(link, p.unlock_keyfile ? "unlockKeyFile" : "unlockKeyFileDescriptorIndex");

                if (p.unlock_keyfile && p.unlock_keyfile_fd_idx >= 0)
                        return sd_varlink_error_invalid_parameter_name(link, "unlockKeyFileDescriptorIndex");

                if (p.unlock_keyfile_fd_idx >= 0) {
                        keyfile_fd = sd_varlink_peek_dup_fd(link, p.unlock_keyfile_fd_idx);
                        if (keyfile_fd < 0)
                                return sd_varlink_error_invalid_parameter_name(link, "unlockKeyFileDescriptorIndex");

                        if (asprintf(&c.unlock_keyfile, "/proc/self/fd/%i", keyfile_fd) < 0)
                                return -ENOMEM;
                } else
                        c.unlock_keyfile = TAKE_PTR(p.unlock_keyfile);

                c.unlock_type = UNLOCK_KEYFILE;
        }

        if (p.unlock_fido2_device) {
                if (c.unlock_type >= 0)
                        return sd_varlink_error_invalid_parameter_name(link, "unlockFido2Device");
                if (strdup_to(&c.unlock_fido2_device, p.unlock_fido2_device) < 0)
                        return -ENOMEM;
                c.unlock_type = UNLOCK_FIDO2;
        }

        if (p.unlock_tpm2_device) {
                if (c.unlock_type >= 0)
                        return sd_varlink_error_invalid_parameter_name(link, "unlockTpm2Device");
                if (strdup_to(&c.unlock_tpm2_device, p.unlock_tpm2_device) < 0)
                        return -ENOMEM;
                c.unlock_type = UNLOCK_TPM2;
        }

        /* If no unlock method is specified, return a recognizable error. We generate invalid parameter name
         * for "unlockPassword", simply because it is the best-known unlock method */
        if (c.unlock_type < 0)
                return sd_varlink_error_invalid_parameter_name(link, "unlockPassword");

        /* Mechanism-specific parameters */
        switch (c.enroll_type) {

        case ENROLL_PASSWORD:
                if (p.password) {
                        c.passphrase = TAKE_PTR(p.password);
                        c.passphrase_size = strlen(c.passphrase);
                }
                break;

        case ENROLL_RECOVERY:
                break;

        case ENROLL_FIDO2:
                /* enroll_fido2() requires a concrete device, so if none was given (NULL), discover one. */
                r = strdup_to(&c.fido2_device, p.fido2_device);
                if (r < 0)
                        return r;
                if (!c.fido2_device) {
                        r = fido2_find_device_auto(&c.fido2_device);
                        if (r < 0)
                                return varlink_error_for_enroll(link, r);
                }

                if (p.fido2_with_client_pin >= 0)
                        SET_FLAG(c.fido2_lock_with, FIDO2ENROLL_PIN, p.fido2_with_client_pin);
                if (p.fido2_with_user_presence >= 0)
                        SET_FLAG(c.fido2_lock_with, FIDO2ENROLL_UP, p.fido2_with_user_presence);
                if (p.fido2_with_user_verification >= 0)
                        SET_FLAG(c.fido2_lock_with, FIDO2ENROLL_UV, p.fido2_with_user_verification);

                c.fido2_pin = TAKE_PTR(p.fido2_pin);
                break;

        default:
                return sd_varlink_error_invalid_parameter_name(link, "mechanism");
        }

        if (p.wipe_slots) {
                r = parse_wipe_slots(p.wipe_slots, &c);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "wipeSlots");
        }
        if (p.wipe_types) {
                r = parse_wipe_types(p.wipe_types, &c);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "wipeTypes");
        }

        /* If the caller asked for 'more', remember the link so we can send progress (e.g. FIDO2 touch). */
        if (FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                c.link = sd_varlink_ref(link);

        r = dlopen_cryptsetup(LOG_ERR);
        if (r < 0)
                return r;

        r = prepare_luks(&c, &cd, &vk);
        if (r < 0)
                return varlink_error_for_enroll(link, r);

        _cleanup_(erase_and_freep) char *recovery_key = NULL;
        slot = enroll_now(&c, cd, &vk, &recovery_key);
        if (slot < 0)
                return varlink_error_for_enroll(link, slot);

        /* Wipe any slots the caller selected, keeping the one we just enrolled. */
        c.wipe_except_slot = slot;
        _cleanup_free_ int *wiped_slots = NULL;
        size_t n_wiped_slots = 0;
        r = wipe_slots(&c, cd, &wiped_slots, &n_wiped_slots);
        if (r < 0)
                return varlink_error_for_enroll(link, r);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *wiped_slots_json = NULL;
        FOREACH_ARRAY(s, wiped_slots, n_wiped_slots) {
                r = sd_json_variant_append_arrayb(&wiped_slots_json, SD_JSON_BUILD_INTEGER(*s));
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *rk = NULL;
        if (recovery_key) {
                r = sd_json_variant_new_string(&rk, recovery_key);
                if (r < 0)
                        return r;

                sd_json_variant_sensitive(rk);
        }

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_INTEGER("keyslot", slot),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("wipedSlots", wiped_slots_json),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("recoveryKey", rk));
}

static int vl_method_list_slots(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "node", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(enroll_context_done) EnrollContext c = ENROLL_CONTEXT_NULL;
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_free_ EnrolledSlot *slots = NULL;
        const char *node = NULL;
        size_t n_slots;
        int r;

        assert(link);

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &node);
        if (r != 0)
                return r;

        /* NB: No polkit authentication here for now, given this is read access only. */

        c.interactive = false;
        if (strdup_to(&c.node, node) < 0)
                return -ENOMEM;

        r = dlopen_cryptsetup(LOG_ERR);
        if (r < 0)
                return r;

        /* We only need to read the LUKS2 header, no volume key required. */
        r = prepare_luks(&c, &cd, /* ret_volume_key= */ NULL);
        if (r < 0)
                return varlink_error_for_enroll(link, r);

        r = collect_enrolled_slots(cd, &slots, &n_slots);
        if (r < 0)
                return r;

        FOREACH_ARRAY(s, slots, n_slots) {
                /* enroll_type_to_string() returns NULL for unrecognized types; conflicts are reported
                 * with no type too. The dash spelling is underscorified for the wire by the build macro. */
                const char *type = s->conflict ? NULL : enroll_type_to_string(s->type);

                r = sd_varlink_notifybo(
                                link,
                                SD_JSON_BUILD_PAIR_INTEGER("slot", s->slot),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY_UNDERSCORIFY("type", type));
                if (r < 0)
                        return r;
        }

        return sd_varlink_reply(link, NULL);
}

int cryptenroll_varlink_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        _cleanup_hashmap_free_ Hashmap *polkit_registry = NULL;
        int r;

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_MYSELF_ONLY|SD_VARLINK_SERVER_INPUT_SENSITIVE|SD_VARLINK_SERVER_INHERIT_USERDATA|SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT|SD_VARLINK_SERVER_HANDLE_SIGINT|SD_VARLINK_SERVER_HANDLE_SIGTERM,
                        &polkit_registry);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_CryptEnroll);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.CryptEnroll.Enroll",    vl_method_enroll,
                        "io.systemd.CryptEnroll.ListSlots", vl_method_list_slots);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}
