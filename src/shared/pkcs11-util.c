/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "ask-password-api.h"
#include "dlfcn-util.h"
#include "env-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-table.h"
#include "io-util.h"
#include "memory-util.h"
#if HAVE_OPENSSL
#include "openssl-util.h"
#endif
#include "pkcs11-util.h"
#include "random-util.h"
#include "string-util.h"
#include "strv.h"

bool pkcs11_uri_valid(const char *uri) {
        const char *p;

        /* A very superficial checker for RFC7512 PKCS#11 URI syntax */

        if (isempty(uri))
                return false;

        p = startswith(uri, "pkcs11:");
        if (!p)
                return false;

        if (isempty(p))
                return false;

        if (!in_charset(p, ALPHANUMERICAL ".~/-_?;&%="))
                return false;

        return true;
}

#if HAVE_P11KIT

static void *p11kit_dl = NULL;

char *(*sym_p11_kit_module_get_name)(CK_FUNCTION_LIST *module);
void (*sym_p11_kit_modules_finalize_and_release)(CK_FUNCTION_LIST **modules);
CK_FUNCTION_LIST **(*sym_p11_kit_modules_load_and_initialize)(int flags);
const char *(*sym_p11_kit_strerror)(CK_RV rv);
int (*sym_p11_kit_uri_format)(P11KitUri *uri, P11KitUriType uri_type, char **string);
void (*sym_p11_kit_uri_free)(P11KitUri *uri);
CK_ATTRIBUTE_PTR (*sym_p11_kit_uri_get_attributes)(P11KitUri *uri, CK_ULONG *n_attrs);
CK_ATTRIBUTE_PTR (*sym_p11_kit_uri_get_attribute)(P11KitUri *uri, CK_ATTRIBUTE_TYPE attr_type);
int (*sym_p11_kit_uri_set_attribute)(P11KitUri *uri, CK_ATTRIBUTE_PTR attr);
CK_INFO_PTR (*sym_p11_kit_uri_get_module_info)(P11KitUri *uri);
CK_SLOT_INFO_PTR (*sym_p11_kit_uri_get_slot_info)(P11KitUri *uri);
CK_TOKEN_INFO_PTR (*sym_p11_kit_uri_get_token_info)(P11KitUri *uri);
int (*sym_p11_kit_uri_match_token_info)(const P11KitUri *uri, const CK_TOKEN_INFO *token_info);
const char *(*sym_p11_kit_uri_message)(int code);
P11KitUri *(*sym_p11_kit_uri_new)(void);
int (*sym_p11_kit_uri_parse)(const char *string, P11KitUriType uri_type, P11KitUri *uri);

int dlopen_p11kit(void) {
        return dlopen_many_sym_or_warn(
                        &p11kit_dl,
                        "libp11-kit.so.0", LOG_DEBUG,
                        DLSYM_ARG(p11_kit_module_get_name),
                        DLSYM_ARG(p11_kit_modules_finalize_and_release),
                        DLSYM_ARG(p11_kit_modules_load_and_initialize),
                        DLSYM_ARG(p11_kit_strerror),
                        DLSYM_ARG(p11_kit_uri_format),
                        DLSYM_ARG(p11_kit_uri_free),
                        DLSYM_ARG(p11_kit_uri_get_attributes),
                        DLSYM_ARG(p11_kit_uri_get_attribute),
                        DLSYM_ARG(p11_kit_uri_set_attribute),
                        DLSYM_ARG(p11_kit_uri_get_module_info),
                        DLSYM_ARG(p11_kit_uri_get_slot_info),
                        DLSYM_ARG(p11_kit_uri_get_token_info),
                        DLSYM_ARG(p11_kit_uri_match_token_info),
                        DLSYM_ARG(p11_kit_uri_message),
                        DLSYM_ARG(p11_kit_uri_new),
                        DLSYM_ARG(p11_kit_uri_parse));
}

int uri_from_string(const char *p, P11KitUri **ret) {
        _cleanup_(sym_p11_kit_uri_freep) P11KitUri *uri = NULL;
        int r;

        assert(p);
        assert(ret);

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        uri = sym_p11_kit_uri_new();
        if (!uri)
                return -ENOMEM;

        if (sym_p11_kit_uri_parse(p, P11_KIT_URI_FOR_ANY, uri) != P11_KIT_URI_OK)
                return -EINVAL;

        *ret = TAKE_PTR(uri);
        return 0;
}

P11KitUri *uri_from_module_info(const CK_INFO *info) {
        P11KitUri *uri;

        assert(info);

        if (dlopen_p11kit() < 0)
                return NULL;

        uri = sym_p11_kit_uri_new();
        if (!uri)
                return NULL;

        *sym_p11_kit_uri_get_module_info(uri) = *info;
        return uri;
}

P11KitUri *uri_from_slot_info(const CK_SLOT_INFO *slot_info) {
        P11KitUri *uri;

        assert(slot_info);

        if (dlopen_p11kit() < 0)
                return NULL;

        uri = sym_p11_kit_uri_new();
        if (!uri)
                return NULL;

        *sym_p11_kit_uri_get_slot_info(uri) = *slot_info;
        return uri;
}

P11KitUri *uri_from_token_info(const CK_TOKEN_INFO *token_info) {
        P11KitUri *uri;

        assert(token_info);

        if (dlopen_p11kit() < 0)
                return NULL;

        uri = sym_p11_kit_uri_new();
        if (!uri)
                return NULL;

        *sym_p11_kit_uri_get_token_info(uri) = *token_info;
        return uri;
}

CK_RV pkcs11_get_slot_list_malloc(
                CK_FUNCTION_LIST *m,
                CK_SLOT_ID **ret_slotids,
                CK_ULONG *ret_n_slotids) {

        CK_RV rv;

        assert(m);
        assert(ret_slotids);
        assert(ret_n_slotids);

        for (unsigned tries = 0; tries < 16; tries++) {
                _cleanup_free_ CK_SLOT_ID *slotids = NULL;
                CK_ULONG n_slotids = 0;

                rv = m->C_GetSlotList(0, NULL, &n_slotids);
                if (rv != CKR_OK)
                        return rv;
                if (n_slotids == 0) {
                        *ret_slotids = NULL;
                        *ret_n_slotids = 0;
                        return CKR_OK;
                }

                slotids = new(CK_SLOT_ID, n_slotids);
                if (!slotids)
                        return CKR_HOST_MEMORY;

                rv = m->C_GetSlotList(0, slotids, &n_slotids);
                if (rv == CKR_OK) {
                        *ret_slotids = TAKE_PTR(slotids);
                        *ret_n_slotids = n_slotids;
                        return CKR_OK;
                }

                if (rv != CKR_BUFFER_TOO_SMALL)
                        return rv;

                /* Hu? Maybe somebody plugged something in and things changed? Let's try again */
        }

        return CKR_BUFFER_TOO_SMALL;
}

char *pkcs11_token_label(const CK_TOKEN_INFO *token_info) {
        char *t;

        /* The label is not NUL terminated and likely padded with spaces, let's make a copy here, so that we
         * can strip that. */
        t = strndup((char*) token_info->label, sizeof(token_info->label));
        if (!t)
                return NULL;

        strstrip(t);
        return t;
}

char *pkcs11_token_manufacturer_id(const CK_TOKEN_INFO *token_info) {
        char *t;

        t = strndup((char*) token_info->manufacturerID, sizeof(token_info->manufacturerID));
        if (!t)
                return NULL;

        strstrip(t);
        return t;
}

char *pkcs11_token_model(const CK_TOKEN_INFO *token_info) {
        char *t;

        t = strndup((char*) token_info->model, sizeof(token_info->model));
        if (!t)
                return NULL;

        strstrip(t);
        return t;
}

int pkcs11_token_login_by_pin(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                const CK_TOKEN_INFO *token_info,
                const char *token_label,
                const void *pin,
                size_t pin_size) {

        CK_RV rv;
        int r;

        assert(m);
        assert(token_info);

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        if (FLAGS_SET(token_info->flags, CKF_PROTECTED_AUTHENTICATION_PATH)) {
                rv = m->C_Login(session, CKU_USER, NULL, 0);
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to log into security token '%s': %s", token_label, sym_p11_kit_strerror(rv));

                log_info("Successfully logged into security token '%s' via protected authentication path.", token_label);
                return 0;
        }

        if (!FLAGS_SET(token_info->flags, CKF_LOGIN_REQUIRED)) {
                log_info("No login into security token '%s' required.", token_label);
                return 0;
        }

        if (!pin)
                return -ENOANO;

        rv = m->C_Login(session, CKU_USER, (CK_UTF8CHAR*) pin, pin_size);
        if (rv == CKR_OK)  {
                log_info("Successfully logged into security token '%s'.", token_label);
                return 0;
        }

        if (rv == CKR_PIN_LOCKED)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "PIN has been locked, please reset PIN of security token '%s'.", token_label);
        if (!IN_SET(rv, CKR_PIN_INCORRECT, CKR_PIN_LEN_RANGE))
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to log into security token '%s': %s", token_label, sym_p11_kit_strerror(rv));

        return log_notice_errno(SYNTHETIC_ERRNO(ENOLCK),
                                "PIN for token '%s' is incorrect, please try again.",
                                token_label);
}

int pkcs11_token_login(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slotid,
                const CK_TOKEN_INFO *token_info,
                const char *friendly_name,
                const char *icon_name,
                const char *key_name,
                const char *credential_name,
                usec_t until,
                AskPasswordFlags ask_password_flags,
                bool headless,
                char **ret_used_pin) {

        _cleanup_free_ char *token_uri_string = NULL, *token_uri_escaped = NULL, *id = NULL, *token_label = NULL;
        _cleanup_(sym_p11_kit_uri_freep) P11KitUri *token_uri = NULL;
        CK_TOKEN_INFO updated_token_info;
        int uri_result, r;
        CK_RV rv;

        assert(m);
        assert(token_info);

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        token_label = pkcs11_token_label(token_info);
        if (!token_label)
                return log_oom();

        token_uri = uri_from_token_info(token_info);
        if (!token_uri)
                return log_oom();

        uri_result = sym_p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, &token_uri_string);
        if (uri_result != P11_KIT_URI_OK)
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Failed to format slot URI: %s", sym_p11_kit_uri_message(uri_result));

        r = pkcs11_token_login_by_pin(m, session, token_info, token_label, /* pin= */ NULL, 0);
        if (r == 0 && ret_used_pin)
                *ret_used_pin = NULL;

        if (r != -ENOANO) /* pin required */
                return r;

        token_uri_escaped = cescape(token_uri_string);
        if (!token_uri_escaped)
                return log_oom();

        id = strjoin("pkcs11:", token_uri_escaped);
        if (!id)
                return log_oom();

        for (unsigned tries = 0; tries < 3; tries++) {
                _cleanup_strv_free_erase_ char **passwords = NULL;
                _cleanup_(erase_and_freep) char *envpin = NULL;

                r = getenv_steal_erase("PIN", &envpin);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire PIN from environment: %m");
                if (r > 0) {
                        passwords = strv_new(envpin);
                        if (!passwords)
                                return log_oom();

                } else if (headless)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "PIN querying disabled via 'headless' option. Use the 'PIN' environment variable.");
                else {
                        _cleanup_free_ char *text = NULL;

                        if (FLAGS_SET(token_info->flags, CKF_USER_PIN_FINAL_TRY))
                                r = asprintf(&text,
                                             "Please enter correct PIN for security token '%s' in order to unlock %s (final try):",
                                             token_label, friendly_name);
                        else if (FLAGS_SET(token_info->flags, CKF_USER_PIN_COUNT_LOW))
                                r = asprintf(&text,
                                             "PIN has been entered incorrectly previously, please enter correct PIN for security token '%s' in order to unlock %s:",
                                             token_label, friendly_name);
                        else if (tries == 0)
                                r = asprintf(&text,
                                             "Please enter PIN for security token '%s' in order to unlock %s:",
                                             token_label, friendly_name);
                        else
                                r = asprintf(&text,
                                             "Please enter PIN for security token '%s' in order to unlock %s (try #%u):",
                                             token_label, friendly_name, tries+1);
                        if (r < 0)
                                return log_oom();

                        /* We never cache PINs, simply because it's fatal if we use wrong PINs, since usually there are only 3 tries */
                        r = ask_password_auto(text, icon_name, id, key_name, credential_name, until, ask_password_flags, &passwords);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query PIN for security token '%s': %m", token_label);
                }

                STRV_FOREACH(i, passwords) {
                        r = pkcs11_token_login_by_pin(m, session, token_info, token_label, *i, strlen(*i));
                        if (r == 0 && ret_used_pin) {
                                char *c;

                                c = strdup(*i);
                                if (!c)
                                        return log_oom();

                                *ret_used_pin = c;
                        }

                        if (r != -ENOLCK)
                                return r;

                        /* Refresh the token info, so that we can prompt knowing the new flags if they changed. */
                        rv = m->C_GetTokenInfo(slotid, &updated_token_info);
                        if (rv != CKR_OK)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                                       "Failed to acquire updated security token information for slot %lu: %s",
                                                       slotid, sym_p11_kit_strerror(rv));

                        token_info = &updated_token_info;
                }
        }

        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Too many attempts to log into token '%s'.", token_label);
}

int pkcs11_token_find_x509_certificate(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                P11KitUri *search_uri,
                CK_OBJECT_HANDLE *ret_object) {

        bool found_class = false, found_certificate_type = false;
        _cleanup_free_ CK_ATTRIBUTE *attributes_buffer = NULL;
        CK_ULONG n_attributes, a, n_objects;
        CK_ATTRIBUTE *attributes = NULL;
        CK_OBJECT_HANDLE objects[2];
        CK_RV rv, rv2;
        int r;

        assert(m);
        assert(search_uri);
        assert(ret_object);

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        attributes = sym_p11_kit_uri_get_attributes(search_uri, &n_attributes);
        for (a = 0; a < n_attributes; a++) {

                /* We use the URI's included match attributes, but make them more strict. This allows users
                 * to specify a token URL instead of an object URL and the right thing should happen if
                 * there's only one suitable key on the token. */

                switch (attributes[a].type) {

                case CKA_CLASS: {
                        CK_OBJECT_CLASS c;

                        if (attributes[a].ulValueLen != sizeof(c))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid PKCS#11 CKA_CLASS attribute size.");

                        memcpy(&c, attributes[a].pValue, sizeof(c));
                        if (c != CKO_CERTIFICATE)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected PKCS#11 object is not an X.509 certificate, refusing.");

                        found_class = true;
                        break;
                }

                case CKA_CERTIFICATE_TYPE: {
                        CK_CERTIFICATE_TYPE t;

                        if (attributes[a].ulValueLen != sizeof(t))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid PKCS#11 CKA_CERTIFICATE_TYPE attribute size.");

                        memcpy(&t, attributes[a].pValue, sizeof(t));
                        if (t != CKC_X_509)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected PKCS#11 object is not an X.509 certificate, refusing.");

                        found_certificate_type = true;
                        break;
                }}
        }

        if (!found_class || !found_certificate_type) {
                /* Hmm, let's slightly extend the attribute list we search for */

                attributes_buffer = new(CK_ATTRIBUTE, n_attributes + !found_class + !found_certificate_type);
                if (!attributes_buffer)
                        return log_oom();

                memcpy(attributes_buffer, attributes, sizeof(CK_ATTRIBUTE) * n_attributes);

                if (!found_class) {
                        static const CK_OBJECT_CLASS class = CKO_CERTIFICATE;

                        attributes_buffer[n_attributes++] = (CK_ATTRIBUTE) {
                                .type = CKA_CLASS,
                                .pValue = (CK_OBJECT_CLASS*) &class,
                                .ulValueLen = sizeof(class),
                        };
                }

                if (!found_certificate_type) {
                        static const CK_CERTIFICATE_TYPE type = CKC_X_509;

                        attributes_buffer[n_attributes++] = (CK_ATTRIBUTE) {
                                .type = CKA_CERTIFICATE_TYPE,
                                .pValue = (CK_CERTIFICATE_TYPE*) &type,
                                .ulValueLen = sizeof(type),
                        };
                }

                attributes = attributes_buffer;
        }

        rv = m->C_FindObjectsInit(session, attributes, n_attributes);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to initialize object find call: %s", sym_p11_kit_strerror(rv));

        rv = m->C_FindObjects(session, objects, ELEMENTSOF(objects), &n_objects);
        rv2 = m->C_FindObjectsFinal(session);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to find objects: %s", sym_p11_kit_strerror(rv));
        if (rv2 != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to finalize object find call: %s", sym_p11_kit_strerror(rv));
        if (n_objects == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Failed to find selected X509 certificate on token.");
        if (n_objects > 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                       "Configured URI matches multiple certificates, refusing.");

        *ret_object = objects[0];
        return 0;
}

#if HAVE_OPENSSL
static int read_public_key_info(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_OBJECT_HANDLE object,
                EVP_PKEY **ret_pkey) {

        CK_ATTRIBUTE attribute = { CKA_PUBLIC_KEY_INFO, NULL_PTR, 0 };
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        CK_RV rv;

        rv = m->C_GetAttributeValue(session, object, &attribute, 1);
        if (rv != CKR_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                "Failed to get size of CKA_PUBLIC_KEY_INFO: %s", sym_p11_kit_strerror(rv));

        if (attribute.ulValueLen == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "CKA_PUBLIC_KEY_INFO is empty");

        _cleanup_free_ void *buffer = malloc(attribute.ulValueLen);
        if (!buffer)
                return log_oom_debug();

        attribute.pValue = buffer;

        rv = m->C_GetAttributeValue(session, object, &attribute, 1);
        if (rv != CKR_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                        "Failed to read CKA_PUBLIC_KEY_INFO: %s", sym_p11_kit_strerror(rv));

        const unsigned char *value = attribute.pValue;
        pkey = d2i_PUBKEY(NULL, &value, attribute.ulValueLen);
        if (!pkey)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to parse CKA_PUBLIC_KEY_INFO");

        *ret_pkey = TAKE_PTR(pkey);
        return 0;
}

int pkcs11_token_read_public_key(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_OBJECT_HANDLE object,
                EVP_PKEY **ret_pkey) {

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        CK_RV rv;
        int r;

        r = read_public_key_info(m, session, object, &pkey);
        if (r >= 0) {
                *ret_pkey = TAKE_PTR(pkey);
                return 0;
        }

        CK_KEY_TYPE key_type;
        CK_ATTRIBUTE attribute = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };

        rv = m->C_GetAttributeValue(session, object, &attribute, 1);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to get CKA_KEY_TYPE of a public key: %s", sym_p11_kit_strerror(rv));

        switch (key_type) {
        case CKK_RSA: {
                CK_ATTRIBUTE rsa_attributes[] = {
                        { CKA_MODULUS,         NULL_PTR, 0 },
                        { CKA_PUBLIC_EXPONENT, NULL_PTR, 0 },
                };

                rv = m->C_GetAttributeValue(session, object, rsa_attributes, ELEMENTSOF(rsa_attributes));
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to get size of attributes of an RSA public key: %s", sym_p11_kit_strerror(rv));

                if (rsa_attributes[0].ulValueLen == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "An RSA public key has empty CKA_MODULUS.");

                _cleanup_free_ void *modulus = malloc(rsa_attributes[0].ulValueLen);
                if (!modulus)
                        return log_oom();

                rsa_attributes[0].pValue = modulus;

                if (rsa_attributes[1].ulValueLen == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "An RSA public key has empty CKA_PUBLIC_EXPONENT.");

                _cleanup_free_ void *public_exponent = malloc(rsa_attributes[1].ulValueLen);
                if (!public_exponent)
                        return log_oom();

                rsa_attributes[1].pValue = public_exponent;

                rv = m->C_GetAttributeValue(session, object, rsa_attributes, ELEMENTSOF(rsa_attributes));
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to get attributes of an RSA public key: %s", sym_p11_kit_strerror(rv));

                size_t n_size = rsa_attributes[0].ulValueLen, e_size = rsa_attributes[1].ulValueLen;
                r = rsa_pkey_from_n_e(rsa_attributes[0].pValue, n_size, rsa_attributes[1].pValue, e_size, &pkey);
                if (r < 0)
                        return log_error_errno(r, "Failed to create an EVP_PKEY from RSA parameters.");

                break;
        }
        case CKK_EC: {
                CK_ATTRIBUTE ec_attributes[] = {
                        { CKA_EC_PARAMS, NULL_PTR, 0 },
                        { CKA_EC_POINT,  NULL_PTR, 0 },
                };

                rv = m->C_GetAttributeValue(session, object, ec_attributes, ELEMENTSOF(ec_attributes));
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to get size of attributes of an EC public key: %s", sym_p11_kit_strerror(rv));

                if (ec_attributes[0].ulValueLen == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "An EC public key has empty CKA_EC_PARAMS.");

                _cleanup_free_ void *ec_group = malloc(ec_attributes[0].ulValueLen);
                if (!ec_group)
                        return log_oom();

                ec_attributes[0].pValue = ec_group;

                if (ec_attributes[1].ulValueLen == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "An EC public key has empty CKA_EC_POINT.");

                _cleanup_free_ void *ec_point = malloc(ec_attributes[1].ulValueLen);
                if (!ec_point)
                        return log_oom();

                ec_attributes[1].pValue = ec_point;

                rv = m->C_GetAttributeValue(session, object, ec_attributes, ELEMENTSOF(ec_attributes));
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to get attributes of an EC public key: %s", sym_p11_kit_strerror(rv));

                _cleanup_(EC_GROUP_freep) EC_GROUP *group = NULL;
                _cleanup_(ASN1_OCTET_STRING_freep) ASN1_OCTET_STRING *os = NULL;

                const unsigned char *ec_params_value = ec_attributes[0].pValue;
                group = d2i_ECPKParameters(NULL, &ec_params_value, ec_attributes[0].ulValueLen);
                if (!group)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unable to decode CKA_EC_PARAMS.");

                const unsigned char *ec_point_value = ec_attributes[1].pValue;
                os = d2i_ASN1_OCTET_STRING(NULL, &ec_point_value, ec_attributes[1].ulValueLen);
                if (!os)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unable to decode CKA_EC_POINT.");

#if OPENSSL_VERSION_MAJOR >= 3
                _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
                if (!ctx)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to create an EVP_PKEY_CTX for EC.");

                if (EVP_PKEY_fromdata_init(ctx) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to init an EVP_PKEY_CTX for EC.");

                OSSL_PARAM ec_params[8] = {
                        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, os->data, os->length)
                };

                _cleanup_free_ void *order = NULL, *p = NULL, *a = NULL, *b = NULL, *generator = NULL;
                size_t order_size, p_size, a_size, b_size, generator_size;

                int nid = EC_GROUP_get_curve_name(group);
                if (nid != NID_undef) {
                        const char* name = OSSL_EC_curve_nid2name(nid);
                        ec_params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)name, strlen(name));
                        ec_params[2] = OSSL_PARAM_construct_end();
                } else {
                        const char *field_type = EC_GROUP_get_field_type(group) == NID_X9_62_prime_field ?
                                "prime-field" : "characteristic-two-field";

                        const BIGNUM *bn_order = EC_GROUP_get0_order(group);

                        _cleanup_(BN_CTX_freep) BN_CTX *bnctx = BN_CTX_new();
                        if (!bnctx)
                                return log_oom();

                        _cleanup_(BN_freep) BIGNUM *bn_p = BN_new();
                        if (!bn_p)
                                return log_oom();

                        _cleanup_(BN_freep) BIGNUM *bn_a = BN_new();
                        if (!bn_a)
                                return log_oom();

                        _cleanup_(BN_freep) BIGNUM *bn_b = BN_new();
                        if (!bn_b)
                                return log_oom();

                        if (EC_GROUP_get_curve(group, bn_p, bn_a, bn_b, bnctx) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to extract EC parameters from EC_GROUP.");

                        order_size = BN_num_bytes(bn_order);
                        p_size = BN_num_bytes(bn_p);
                        a_size = BN_num_bytes(bn_a);
                        b_size = BN_num_bytes(bn_b);

                        order = malloc(order_size);
                        if (!order)
                                return log_oom();

                        p = malloc(p_size);
                        if (!p)
                                return log_oom();

                        a = malloc(a_size);
                        if (!a)
                                return log_oom();

                        b = malloc(b_size);
                        if (!b)
                                return log_oom();

                        if (BN_bn2nativepad(bn_order, order, order_size) <= 0 ||
                            BN_bn2nativepad(bn_p, p, p_size) <= 0 ||
                            BN_bn2nativepad(bn_a, a, a_size) <= 0 ||
                            BN_bn2nativepad(bn_b, b, b_size) <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to store EC parameters in native byte order.");

                        const EC_POINT *point_gen = EC_GROUP_get0_generator(group);
                        generator_size = EC_POINT_point2oct(group, point_gen, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bnctx);
                        if (generator_size == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to determine size of a EC generator.");

                        generator = malloc(generator_size);
                        if (!generator)
                                return log_oom();

                        generator_size = EC_POINT_point2oct(group, point_gen, POINT_CONVERSION_UNCOMPRESSED, generator, generator_size, bnctx);
                        if (generator_size == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert a EC generator to octet string.");

                        ec_params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, (char*)field_type, strlen(field_type));
                        ec_params[2] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, generator, generator_size);
                        ec_params[3] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_EC_ORDER, order, order_size);
                        ec_params[4] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_EC_P, p, p_size);
                        ec_params[5] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_EC_A, a, a_size);
                        ec_params[6] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_EC_B, b, b_size);
                        ec_params[7] = OSSL_PARAM_construct_end();
                }

                if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, ec_params) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to create EVP_PKEY from EC parameters.");
#else
                _cleanup_(EC_POINT_freep) EC_POINT *point = EC_POINT_new(group);
                if (!point)
                        return log_oom();

                if (EC_POINT_oct2point(group, point, os->data, os->length, NULL) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unable to decode CKA_EC_POINT.");

                 _cleanup_(EC_KEY_freep) EC_KEY *ec_key = EC_KEY_new();
                if (!ec_key)
                        return log_oom();

                if (EC_KEY_set_group(ec_key, group) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set group for EC_KEY.");

                if (EC_KEY_set_public_key(ec_key, point) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set public key for EC_KEY.");

                pkey = EVP_PKEY_new();
                if (!pkey)
                        return log_oom();

                if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to assign EC_KEY to EVP_PKEY.");
#endif
                break;
        }
        default:
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported type of public key: %lu", key_type);
        }

        *ret_pkey = TAKE_PTR(pkey);
        return 0;
}

int pkcs11_token_read_x509_certificate(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_OBJECT_HANDLE object,
                X509 **ret_cert) {

        _cleanup_free_ void *buffer = NULL;
        _cleanup_free_ char *t = NULL;
        CK_ATTRIBUTE attribute = {
                .type = CKA_VALUE
        };
        CK_RV rv;
        _cleanup_(X509_freep) X509 *x509 = NULL;
        X509_NAME *name = NULL;
        const unsigned char *p;
        int r;

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        rv = m->C_GetAttributeValue(session, object, &attribute, 1);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to read X.509 certificate size off token: %s", sym_p11_kit_strerror(rv));

        buffer = malloc(attribute.ulValueLen);
        if (!buffer)
                return log_oom();

        attribute.pValue = buffer;

        rv = m->C_GetAttributeValue(session, object, &attribute, 1);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to read X.509 certificate data off token: %s", sym_p11_kit_strerror(rv));

        p = attribute.pValue;
        x509 = d2i_X509(NULL, &p, attribute.ulValueLen);
        if (!x509)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to parse X.509 certificate.");

        name = X509_get_subject_name(x509);
        if (!name)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to acquire X.509 subject name.");

        t = X509_NAME_oneline(name, NULL, 0);
        if (!t)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to format X.509 subject name as string.");

        log_debug("Using X.509 certificate issued for '%s'.", t);

        *ret_cert = TAKE_PTR(x509);
        return 0;
}
#endif

int pkcs11_token_find_private_key(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                P11KitUri *search_uri,
                CK_OBJECT_HANDLE *ret_object) {

        uint_fast8_t n_objects = 0;
        bool found_class = false;
        _cleanup_free_ CK_ATTRIBUTE *attributes_buffer = NULL;
        CK_OBJECT_HANDLE object, candidate;
        static const CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
        CK_BBOOL decrypt_value, derive_value;
        CK_ATTRIBUTE optional_attributes[] = {
                { CKA_DECRYPT, &decrypt_value, sizeof(decrypt_value) },
                { CKA_DERIVE,  &derive_value,  sizeof(derive_value)  }
        };
        CK_RV rv;

        assert(m);
        assert(search_uri);
        assert(ret_object);

        CK_ULONG n_attributes;
        CK_ATTRIBUTE *attributes = sym_p11_kit_uri_get_attributes(search_uri, &n_attributes);
        for (CK_ULONG i = 0; i < n_attributes; i++) {

                /* We use the URI's included match attributes, but make them more strict. This allows users
                 * to specify a token URL instead of an object URL and the right thing should happen if
                 * there's only one suitable key on the token. */

                switch (attributes[i].type) {
                case CKA_CLASS: {
                        CK_OBJECT_CLASS c;

                        if (attributes[i].ulValueLen != sizeof(c))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid PKCS#11 CKA_CLASS attribute size.");

                        memcpy(&c, attributes[i].pValue, sizeof(c));
                        if (c != CKO_PRIVATE_KEY)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Selected PKCS#11 object is not a private key, refusing.");

                        found_class = true;
                        break;
                }}
        }

        if (!found_class) {
                /* Hmm, let's slightly extend the attribute list we search for */

                attributes_buffer = new(CK_ATTRIBUTE, n_attributes + 1);
                if (!attributes_buffer)
                        return log_oom();

                memcpy(attributes_buffer, attributes, sizeof(CK_ATTRIBUTE) * n_attributes);

                attributes_buffer[n_attributes++] = (CK_ATTRIBUTE) {
                        .type = CKA_CLASS,
                        .pValue = (CK_OBJECT_CLASS*) &class,
                        .ulValueLen = sizeof(class),
                };

                attributes = attributes_buffer;
        }

        rv = m->C_FindObjectsInit(session, attributes, n_attributes);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to initialize object find call: %s", sym_p11_kit_strerror(rv));

        for (;;) {
                CK_ULONG b;
                rv = m->C_FindObjects(session, &candidate, 1, &b);
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to find objects: %s", sym_p11_kit_strerror(rv));

                if (b == 0)
                        break;

                bool can_decrypt = false, can_derive = false;
                optional_attributes[0].ulValueLen = sizeof(decrypt_value);
                optional_attributes[1].ulValueLen = sizeof(derive_value);

                rv = m->C_GetAttributeValue(session, candidate, optional_attributes, ELEMENTSOF(optional_attributes));
                if (!IN_SET(rv, CKR_OK, CKR_ATTRIBUTE_TYPE_INVALID))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to get attributes of a selected private key: %s", sym_p11_kit_strerror(rv));

                if (optional_attributes[0].ulValueLen != CK_UNAVAILABLE_INFORMATION && decrypt_value == CK_TRUE)
                        can_decrypt = true;

                if (optional_attributes[1].ulValueLen != CK_UNAVAILABLE_INFORMATION && derive_value == CK_TRUE)
                        can_derive = true;

                if (can_decrypt || can_derive) {
                        n_objects++;
                        if (n_objects > 1)
                                break;
                        object = candidate;
                }
        }

        rv = m->C_FindObjectsFinal(session);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                        "Failed to finalize object find call: %s", sym_p11_kit_strerror(rv));

        if (n_objects == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                        "Failed to find selected private key suitable for decryption or derivation on token.");

        if (n_objects > 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                        "Configured private key URI matches multiple keys, refusing.");

        *ret_object = object;
        return 0;
}

static const char* object_class_to_string(CK_OBJECT_CLASS class) {
        switch (class) {
        case CKO_CERTIFICATE:
                return "CKO_CERTIFICATE";
        case CKO_PUBLIC_KEY:
                return "CKO_PUBLIC_KEY";
        case CKO_PRIVATE_KEY:
                return "CKO_PRIVATE_KEY";
        case CKO_SECRET_KEY:
                return "CKO_SECRET_KEY";
        default:
                return NULL;
        }
}

/* Returns an object with the given class and the same CKA_ID or CKA_LABEL as prototype */
int pkcs11_token_find_related_object(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_OBJECT_HANDLE prototype,
                CK_OBJECT_CLASS class,
                CK_OBJECT_HANDLE *ret_object ) {

        _cleanup_free_ void *buffer = NULL;
        CK_ATTRIBUTE attributes[] = {
                { CKA_ID,    NULL_PTR, 0 },
                { CKA_LABEL, NULL_PTR, 0 }
        };
        CK_OBJECT_CLASS search_class = class;
        CK_ATTRIBUTE search_attributes[2] = {
                { CKA_CLASS, &search_class, sizeof(search_class) }
        };
        CK_ULONG n_objects;
        CK_OBJECT_HANDLE objects[2];
        CK_RV rv;

        rv = m->C_GetAttributeValue(session, prototype, attributes, ELEMENTSOF(attributes));
        if (!IN_SET(rv, CKR_OK, CKR_ATTRIBUTE_TYPE_INVALID))
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve length of attributes: %s", sym_p11_kit_strerror(rv));

        if (attributes[0].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
                buffer = malloc(attributes[0].ulValueLen);
                if (!buffer)
                        return log_oom();

                attributes[0].pValue = buffer;
                rv = m->C_GetAttributeValue(session, prototype, &attributes[0], 1);
                if (rv != CKR_OK)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to retrieve CKA_ID: %s", sym_p11_kit_strerror(rv));

                search_attributes[1] = attributes[0];

        } else if (attributes[1].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
                buffer = malloc(attributes[1].ulValueLen);
                if (!buffer)
                        return log_oom();

                attributes[1].pValue = buffer;
                rv = m->C_GetAttributeValue(session, prototype, &attributes[1], 1);
                if (rv != CKR_OK)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to retrieve CKA_LABEL: %s", sym_p11_kit_strerror(rv));

                search_attributes[1] = attributes[1];

        } else
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "The prototype does not have CKA_ID or CKA_LABEL");

        rv = m->C_FindObjectsInit(session, search_attributes, 2);
        if (rv != CKR_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                        "Failed to initialize object find call: %s", sym_p11_kit_strerror(rv));

        rv = m->C_FindObjects(session, objects, 2, &n_objects);
        if (rv != CKR_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                        "Failed to find objects: %s", sym_p11_kit_strerror(rv));

        rv = m->C_FindObjectsFinal(session);
        if (rv != CKR_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                        "Failed to finalize object find call: %s", sym_p11_kit_strerror(rv));

         if (n_objects == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                        "Failed to find a related object with class %s", object_class_to_string(class));

         if (n_objects > 1)
                log_warning("Found multiple related objects with class %s, using the first object.",
                        object_class_to_string(class));

        *ret_object = objects[0];
        return 0;
}

#if HAVE_OPENSSL
static int ecc_convert_to_compressed(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_OBJECT_HANDLE object,
                const void *uncompressed_point,
                size_t uncompressed_point_size,
                void **ret_compressed_point,
                size_t *ret_compressed_point_size) {

        _cleanup_free_ void *ec_params_buffer = NULL;
        CK_ATTRIBUTE ec_params_attr = { CKA_EC_PARAMS, NULL_PTR, 0 };
        CK_RV rv;
        int r;

        rv = m->C_GetAttributeValue(session, object, &ec_params_attr, 1);
        if (!IN_SET(rv, CKR_OK, CKR_ATTRIBUTE_TYPE_INVALID))
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                        "Failed to retrieve length of CKA_EC_PARAMS: %s", sym_p11_kit_strerror(rv));

        if (ec_params_attr.ulValueLen != CK_UNAVAILABLE_INFORMATION) {
                ec_params_buffer = malloc(ec_params_attr.ulValueLen);
                if (!ec_params_buffer)
                        return log_oom();

                ec_params_attr.pValue = ec_params_buffer;
                rv = m->C_GetAttributeValue(session, object, &ec_params_attr, 1);
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to retrieve CKA_EC_PARAMS from a private key: %s", sym_p11_kit_strerror(rv));
        } else {
                CK_OBJECT_HANDLE public_key;
                r = pkcs11_token_find_related_object(m, session, object, CKO_PUBLIC_KEY, &public_key);
                if (r < 0)
                        return log_error_errno(r, "Failed to find a public key for compressing a EC point");

                ec_params_attr.ulValueLen = 0;
                rv = m->C_GetAttributeValue(session, public_key, &ec_params_attr, 1);
                if (!IN_SET(rv, CKR_OK, CKR_ATTRIBUTE_TYPE_INVALID))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to retrieve length of CKA_EC_PARAMS: %s", sym_p11_kit_strerror(rv));

                if (ec_params_attr.ulValueLen == CK_UNAVAILABLE_INFORMATION)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                "The public key does not have CKA_EC_PARAMS");

                ec_params_buffer = malloc(ec_params_attr.ulValueLen);
                if (!ec_params_buffer)
                        return log_oom();

                ec_params_attr.pValue = ec_params_buffer;
                rv = m->C_GetAttributeValue(session, public_key, &ec_params_attr, 1);
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to retrieve CKA_EC_PARAMS from a public key: %s", sym_p11_kit_strerror(rv));
        }

        _cleanup_(EC_GROUP_freep) EC_GROUP *group = NULL;
        _cleanup_(EC_POINT_freep) EC_POINT *point = NULL;
        _cleanup_(BN_CTX_freep) BN_CTX *bnctx = NULL;
        _cleanup_free_ void *compressed_point = NULL;
        size_t compressed_point_size;

        const unsigned char *ec_params_value = ec_params_attr.pValue;
        group = d2i_ECPKParameters(NULL, &ec_params_value, ec_params_attr.ulValueLen);
        if (!group)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unable to decode CKA_EC_PARAMS");

        point = EC_POINT_new(group);
        if (!point)
                return log_oom();

        bnctx = BN_CTX_new();
        if (!bnctx)
                return log_oom();

        if (EC_POINT_oct2point(group, point, uncompressed_point, uncompressed_point_size, bnctx) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unable to decode an uncompressed EC point");

        compressed_point_size = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, bnctx);
        if (compressed_point_size == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to determine size of a compressed EC point");

        compressed_point = malloc(compressed_point_size);
        if (!compressed_point)
                return log_oom();

        compressed_point_size = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, compressed_point, compressed_point_size, bnctx);
        if (compressed_point_size == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert a EC point to compressed format");

        *ret_compressed_point = TAKE_PTR(compressed_point);
        *ret_compressed_point_size = compressed_point_size;
        return 0;
}
#endif

/* Since EC keys doesn't support encryption directly, we use ECDH protocol to derive shared secret here.
 * We use PKCS#11 C_DeriveKey function to derive a shared secret with a private key stored in the token and
 * a public key saved on enrollment. */
static int pkcs11_token_decrypt_data_ecc(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_OBJECT_HANDLE object,
                const void *encrypted_data,
                size_t encrypted_data_size,
                void **ret_decrypted_data,
                size_t *ret_decrypted_data_size) {

        static const CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
        static const CK_OBJECT_CLASS shared_secret_class = CKO_SECRET_KEY;
        static const CK_KEY_TYPE shared_secret_type = CKK_GENERIC_SECRET;
        static const CK_ATTRIBUTE shared_secret_template[] = {
                { CKA_TOKEN,       (void*) &no,                  sizeof(no)                  },
                { CKA_CLASS,       (void*) &shared_secret_class, sizeof(shared_secret_class) },
                { CKA_KEY_TYPE,    (void*) &shared_secret_type,  sizeof(shared_secret_type)  },
                { CKA_SENSITIVE,   (void*) &no,                  sizeof(no)                  },
                { CKA_EXTRACTABLE, (void*) &yes,                 sizeof(yes)                 }
        };
        CK_ECDH1_DERIVE_PARAMS params = {
                .kdf = CKD_NULL,
                .pPublicData = (void*) encrypted_data,
                .ulPublicDataLen = encrypted_data_size
        };
        CK_MECHANISM mechanism = {
                .mechanism = CKM_ECDH1_DERIVE,
                .pParameter = &params,
                .ulParameterLen = sizeof(params)
        };
        CK_OBJECT_HANDLE shared_secret_handle;
        CK_SESSION_INFO session_info;
        CK_MECHANISM_INFO mechanism_info;
        CK_RV rv, rv2;
#if HAVE_OPENSSL
        _cleanup_free_ void *compressed_point = NULL;
        int r;
#endif

        rv = m->C_GetSessionInfo(session, &session_info);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                        "Failed to get information about the PKCS#11 session: %s", sym_p11_kit_strerror(rv));

        rv = m->C_GetMechanismInfo(session_info.slotID, CKM_ECDH1_DERIVE, &mechanism_info);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                        "Failed to get information about CKM_ECDH1_DERIVE: %s", sym_p11_kit_strerror(rv));

        if (!(mechanism_info.flags & CKF_EC_UNCOMPRESS)) {
                if (mechanism_info.flags & CKF_EC_COMPRESS) {
#if HAVE_OPENSSL
                        log_debug("CKM_ECDH1_DERIVE accepts compressed EC points only, trying to convert.");
                        size_t compressed_point_size = 0; /* Explicit initialization to appease gcc */
                        r = ecc_convert_to_compressed(m, session, object, encrypted_data, encrypted_data_size, &compressed_point, &compressed_point_size);
                        if (r < 0)
                                return r;

                        params.pPublicData = compressed_point;
                        params.ulPublicDataLen = compressed_point_size;
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "CKM_ECDH1_DERIVE does not support uncompressed format of EC points");
#endif
                } else
                        log_debug("Both CKF_EC_UNCOMPRESS and CKF_EC_COMPRESS are false for CKM_ECDH1_DERIVE, ignoring.");
        }

        rv = m->C_DeriveKey(session, &mechanism, object, (CK_ATTRIBUTE*) shared_secret_template, ELEMENTSOF(shared_secret_template), &shared_secret_handle);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to derive a shared secret: %s", sym_p11_kit_strerror(rv));

        CK_ATTRIBUTE shared_secret_attr = { CKA_VALUE, NULL_PTR, 0};

        rv = m->C_GetAttributeValue(session, shared_secret_handle, &shared_secret_attr, 1);
        if (rv != CKR_OK) {
                rv2 = m->C_DestroyObject(session, shared_secret_handle);
                if (rv2 != CKR_OK)
                        log_warning("Failed to destroy a shared secret, ignoring: %s", sym_p11_kit_strerror(rv2));
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve shared secret length: %s", sym_p11_kit_strerror(rv));
        }

        shared_secret_attr.pValue = malloc(shared_secret_attr.ulValueLen);
        if (!shared_secret_attr.pValue)
                return log_oom();

        rv = m->C_GetAttributeValue(session, shared_secret_handle, &shared_secret_attr, 1);
        rv2 = m->C_DestroyObject(session, shared_secret_handle);
        if (rv2 != CKR_OK)
                log_warning("Failed to destroy a shared secret, ignoring: %s", sym_p11_kit_strerror(rv2));

        if (rv != CKR_OK) {
                erase_and_free(shared_secret_attr.pValue);
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve a shared secret: %s", sym_p11_kit_strerror(rv));
        }

        log_info("Successfully derived key with security token.");

        *ret_decrypted_data = shared_secret_attr.pValue;
        *ret_decrypted_data_size = shared_secret_attr.ulValueLen;
        return 0;
}

static int pkcs11_token_decrypt_data_rsa(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_OBJECT_HANDLE object,
                const void *encrypted_data,
                size_t encrypted_data_size,
                void **ret_decrypted_data,
                size_t *ret_decrypted_data_size) {

        static const CK_MECHANISM mechanism = {
                 .mechanism = CKM_RSA_PKCS
        };
        _cleanup_(erase_and_freep) CK_BYTE *dbuffer = NULL;
        CK_ULONG dbuffer_size = 0;
        CK_RV rv;

        rv = m->C_DecryptInit(session, (CK_MECHANISM*) &mechanism, object);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to initialize decryption on security token: %s", sym_p11_kit_strerror(rv));

        dbuffer_size = encrypted_data_size; /* Start with something reasonable */
        dbuffer = malloc(dbuffer_size);
        if (!dbuffer)
                return log_oom();

        rv = m->C_Decrypt(session, (CK_BYTE*) encrypted_data, encrypted_data_size, dbuffer, &dbuffer_size);
        if (rv == CKR_BUFFER_TOO_SMALL) {
                erase_and_free(dbuffer);

                dbuffer = malloc(dbuffer_size);
                if (!dbuffer)
                        return log_oom();

                rv = m->C_Decrypt(session, (CK_BYTE*) encrypted_data, encrypted_data_size, dbuffer, &dbuffer_size);
        }
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to decrypt key on security token: %s", sym_p11_kit_strerror(rv));

        log_info("Successfully decrypted key with security token.");

        *ret_decrypted_data = TAKE_PTR(dbuffer);
        *ret_decrypted_data_size = dbuffer_size;
        return 0;
}

int pkcs11_token_decrypt_data(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_OBJECT_HANDLE object,
                const void *encrypted_data,
                size_t encrypted_data_size,
                void **ret_decrypted_data,
                size_t *ret_decrypted_data_size) {

        CK_KEY_TYPE key_type;
        CK_ATTRIBUTE key_type_template = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
        CK_RV rv;

        assert(m);
        assert(encrypted_data);
        assert(encrypted_data_size > 0);
        assert(ret_decrypted_data);
        assert(ret_decrypted_data_size);

        rv = m->C_GetAttributeValue(session, object, &key_type_template, 1);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve private key type");

        switch (key_type) {

        case CKK_RSA:
                return pkcs11_token_decrypt_data_rsa(m, session, object, encrypted_data, encrypted_data_size, ret_decrypted_data, ret_decrypted_data_size);

        case CKK_EC:
                return pkcs11_token_decrypt_data_ecc(m, session, object, encrypted_data, encrypted_data_size, ret_decrypted_data, ret_decrypted_data_size);

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported private key type: %lu", key_type);
        }
}

int pkcs11_token_acquire_rng(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session) {

        _cleanup_free_ void *buffer = NULL;
        size_t rps;
        CK_RV rv;
        int r;

        assert(m);

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        /* While we are at it, let's read some RNG data from the PKCS#11 token and pass it to the kernel
         * random pool. This should be cheap if we are talking to the device already. Note that we don't
         * credit any entropy, since we don't know about the quality of the pkcs#11 token's RNG. Why bother
         * at all? There are two sides to the argument whether to generate private keys on tokens or on the
         * host. By crediting some data from the token RNG to the host's pool we at least can say that any
         * key generated from it is at least as good as both sources individually. */

        rps = random_pool_size();

        buffer = malloc(rps);
        if (!buffer)
                return log_oom();

        rv = m->C_GenerateRandom(session, buffer, rps);
        if (rv != CKR_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Failed to generate RNG data on security token: %s", sym_p11_kit_strerror(rv));

        r = random_write_entropy(-1, buffer, rps, false);
        if (r < 0)
                return log_debug_errno(r, "Failed to write PKCS#11 acquired random data to /dev/urandom: %m");

        log_debug("Successfully written %zu bytes random data acquired via PKCS#11 to kernel random pool.", rps);

        return 0;
}

static int token_process(
                CK_FUNCTION_LIST *m,
                CK_SLOT_ID slotid,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *search_uri,
                pkcs11_find_token_callback_t callback,
                void *userdata) {

        _cleanup_free_ char *token_label = NULL;
        CK_SESSION_HANDLE session;
        CK_RV rv;
        int r;

        assert(m);
        assert(slot_info);
        assert(token_info);

        token_label = pkcs11_token_label(token_info);
        if (!token_label)
                return log_oom();

        rv = m->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to create session for security token '%s': %s", token_label, sym_p11_kit_strerror(rv));

        if (callback)
                r = callback(m, session, slotid, slot_info, token_info, search_uri, userdata);
        else
                r = 1; /* if not callback was specified, just say we found what we were looking for */

        rv = m->C_CloseSession(session);
        if (rv != CKR_OK)
                log_warning("Failed to close session on PKCS#11 token, ignoring: %s", sym_p11_kit_strerror(rv));

        return r;
}

static int slot_process(
                CK_FUNCTION_LIST *m,
                CK_SLOT_ID slotid,
                P11KitUri *search_uri,
                pkcs11_find_token_callback_t callback,
                void *userdata) {

        _cleanup_(sym_p11_kit_uri_freep) P11KitUri* slot_uri = NULL, *token_uri = NULL;
        _cleanup_free_ char *token_uri_string = NULL;
        CK_TOKEN_INFO token_info;
        CK_SLOT_INFO slot_info;
        int uri_result, r;
        CK_RV rv;

        assert(m);

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        /* We return -EAGAIN for all failures we can attribute to a specific slot in some way, so that the
         * caller might try other slots before giving up. */

        rv = m->C_GetSlotInfo(slotid, &slot_info);
        if (rv != CKR_OK) {
                log_warning("Failed to acquire slot info for slot %lu, ignoring slot: %s", slotid, sym_p11_kit_strerror(rv));
                return -EAGAIN;
        }

        slot_uri = uri_from_slot_info(&slot_info);
        if (!slot_uri)
                return log_oom();

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *slot_uri_string = NULL;

                uri_result = sym_p11_kit_uri_format(slot_uri, P11_KIT_URI_FOR_ANY, &slot_uri_string);
                if (uri_result != P11_KIT_URI_OK) {
                        log_warning("Failed to format slot URI, ignoring slot: %s", sym_p11_kit_uri_message(uri_result));
                        return -EAGAIN;
                }

                log_debug("Found slot with URI %s", slot_uri_string);
        }

        rv = m->C_GetTokenInfo(slotid, &token_info);
        if (rv == CKR_TOKEN_NOT_PRESENT) {
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "Token not present in slot, ignoring.");
        } else if (rv != CKR_OK) {
                log_warning("Failed to acquire token info for slot %lu, ignoring slot: %s", slotid, sym_p11_kit_strerror(rv));
                return -EAGAIN;
        }

        token_uri = uri_from_token_info(&token_info);
        if (!token_uri)
                return log_oom();

        uri_result = sym_p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, &token_uri_string);
        if (uri_result != P11_KIT_URI_OK) {
                log_warning("Failed to format slot URI: %s", sym_p11_kit_uri_message(uri_result));
                return -EAGAIN;
        }

        if (search_uri && !sym_p11_kit_uri_match_token_info(search_uri, &token_info))
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "Found non-matching token with URI %s.",
                                       token_uri_string);

        log_debug("Found matching token with URI %s.", token_uri_string);

        return token_process(
                        m,
                        slotid,
                        &slot_info,
                        &token_info,
                        search_uri,
                        callback,
                        userdata);
}

static int module_process(
                CK_FUNCTION_LIST *m,
                P11KitUri *search_uri,
                pkcs11_find_token_callback_t callback,
                void *userdata) {

        _cleanup_(sym_p11_kit_uri_freep) P11KitUri* module_uri = NULL;
        _cleanup_free_ char *name = NULL, *module_uri_string = NULL;
        _cleanup_free_ CK_SLOT_ID *slotids = NULL;
        CK_ULONG n_slotids = 0;
        int uri_result;
        CK_INFO info;
        size_t k;
        CK_RV rv;
        int r;

        assert(m);

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        /* We ignore most errors from modules here, in order to skip over faulty modules: one faulty module
         * should not have the effect that we don't try the others anymore. We indicate such per-module
         * failures with -EAGAIN, which let's the caller try the next module. */

        name = sym_p11_kit_module_get_name(m);
        if (!name)
                return log_oom();

        log_debug("Trying PKCS#11 module %s.", name);

        rv = m->C_GetInfo(&info);
        if (rv != CKR_OK) {
                log_warning("Failed to get info on PKCS#11 module, ignoring module: %s", sym_p11_kit_strerror(rv));
                return -EAGAIN;
        }

        module_uri = uri_from_module_info(&info);
        if (!module_uri)
                return log_oom();

        uri_result = sym_p11_kit_uri_format(module_uri, P11_KIT_URI_FOR_ANY, &module_uri_string);
        if (uri_result != P11_KIT_URI_OK) {
                log_warning("Failed to format module URI, ignoring module: %s", sym_p11_kit_uri_message(uri_result));
                return -EAGAIN;
        }

        log_debug("Found module with URI %s", module_uri_string);

        rv = pkcs11_get_slot_list_malloc(m, &slotids, &n_slotids);
        if (rv != CKR_OK) {
                log_warning("Failed to get slot list, ignoring module: %s", sym_p11_kit_strerror(rv));
                return -EAGAIN;
        }
        if (n_slotids == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "This module has no slots? Ignoring module.");

        for (k = 0; k < n_slotids; k++) {
                r = slot_process(
                                m,
                                slotids[k],
                                search_uri,
                                callback,
                                userdata);
                if (r != -EAGAIN)
                        return r;
        }

        return -EAGAIN;
}

int pkcs11_find_token(
                const char *pkcs11_uri,
                pkcs11_find_token_callback_t callback,
                void *userdata) {

        _cleanup_(sym_p11_kit_modules_finalize_and_releasep) CK_FUNCTION_LIST **modules = NULL;
        _cleanup_(sym_p11_kit_uri_freep) P11KitUri *search_uri = NULL;
        int r;

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        /* Execute the specified callback for each matching token found. If nothing is found returns
         * -EAGAIN. Logs about all errors, except for EAGAIN, which the caller has to log about. */

        if (pkcs11_uri) {
                r = uri_from_string(pkcs11_uri, &search_uri);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse PKCS#11 URI '%s': %m", pkcs11_uri);
        }

        modules = sym_p11_kit_modules_load_and_initialize(0);
        if (!modules)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize pkcs11 modules");

        for (CK_FUNCTION_LIST **i = modules; *i; i++) {
                r = module_process(
                                *i,
                                search_uri,
                                callback,
                                userdata);
                if (r != -EAGAIN)
                        return r;
        }

        return -EAGAIN;
}

#if HAVE_OPENSSL
struct pkcs11_acquire_public_key_callback_data {
        char *pin_used;
        EVP_PKEY *pkey;
        const char *askpw_friendly_name, *askpw_icon_name;
        AskPasswordFlags askpw_flags;
        bool headless;
};

static void pkcs11_acquire_public_key_callback_data_release(struct pkcs11_acquire_public_key_callback_data *data) {
        erase_and_free(data->pin_used);
        EVP_PKEY_free(data->pkey);
}

static int pkcs11_acquire_public_key_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        _cleanup_(erase_and_freep) char *pin_used = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        CK_OBJECT_CLASS class;
        CK_CERTIFICATE_TYPE type;
        CK_ATTRIBUTE candidate_attributes[] = {
                { CKA_CLASS,            &class,   sizeof(class) },
                { CKA_CERTIFICATE_TYPE, &type,    sizeof(type)  },
        };
        CK_OBJECT_HANDLE candidate, public_key, certificate;
        uint8_t n_public_keys = 0, n_certificates = 0;
        CK_RV rv;
        int r;

        assert(m);
        assert(slot_info);
        assert(token_info);
        assert(uri);

        struct pkcs11_acquire_public_key_callback_data *data = ASSERT_PTR(userdata);

        /* Called for every token matching our URI */

        r = pkcs11_token_login(
                        m,
                        session,
                        slot_id,
                        token_info,
                        data->askpw_friendly_name,
                        data->askpw_icon_name,
                        "pkcs11-pin",
                        "pkcs11-pin",
                        UINT64_MAX,
                        data->askpw_flags,
                        data->headless,
                        &pin_used);
        if (r < 0)
                return r;

        CK_ULONG n_attributes;
        CK_ATTRIBUTE *attributes = sym_p11_kit_uri_get_attributes(uri, &n_attributes);
        for (CK_ULONG i = 0; i < n_attributes; i++) {
                switch (attributes[i].type) {
                case CKA_CLASS: {
                        CK_OBJECT_CLASS requested_class = *((CK_OBJECT_CLASS*) attributes[i].pValue);
                        if (requested_class != CKO_PUBLIC_KEY && requested_class != CKO_CERTIFICATE)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Selected PKCS#11 object is not a public key or certificate, refusing.");
                        break;
                }

                case CKA_CERTIFICATE_TYPE: {
                        CK_CERTIFICATE_TYPE requested_type = *((CK_CERTIFICATE_TYPE*) attributes[i].pValue);
                        if (requested_type != CKC_X_509)
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Selected PKCS#11 object is not an X.509 certificate, refusing.");
                        break;
                }}
        }

        rv = m->C_FindObjectsInit(session, attributes, n_attributes);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to initialize object find call: %s", sym_p11_kit_strerror(rv));

        for (;;) {
                CK_ULONG n;
                rv = m->C_FindObjects(session, &candidate, 1, &n);
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to find objects: %s", sym_p11_kit_strerror(rv));

                if (n == 0)
                        break;

                candidate_attributes[0].ulValueLen = sizeof(class);
                candidate_attributes[1].ulValueLen = sizeof(type);
                rv = m->C_GetAttributeValue(session, candidate, candidate_attributes, ELEMENTSOF(candidate_attributes));
                if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                "Failed to get attributes of a selected candidate: %s", sym_p11_kit_strerror(rv));

                if (candidate_attributes[0].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                        log_debug("Failed to get CKA_CLASS of a selected candidate");
                        continue;
                }

                CK_OBJECT_CLASS candidate_class = *((CK_OBJECT_CLASS*) candidate_attributes[0].pValue);

                if (candidate_class == CKO_PUBLIC_KEY) {
                        n_public_keys++;
                        if (n_public_keys > 1)
                                break;
                        public_key = candidate;
                        continue;
                }

                if (candidate_class == CKO_CERTIFICATE) {
                        if (candidate_attributes[1].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                                log_debug("Failed to get CKA_CERTIFICATE_TYPE of a selected candidate");
                                continue;
                        }
                        CK_CERTIFICATE_TYPE candidate_type = *((CK_CERTIFICATE_TYPE*) candidate_attributes[1].pValue);
                        if (candidate_type != CKC_X_509)
                                continue;
                        n_certificates++;
                        if (n_certificates > 1)
                                break;
                        certificate = candidate;
                        continue;
                }
        }

        rv = m->C_FindObjectsFinal(session);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                        "Failed to finalize object find call: %s", sym_p11_kit_strerror(rv));

        if (n_public_keys == 0 && n_certificates == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                        "Failed to find selected public key or certificate on token.");

        if (n_public_keys > 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                        "Provided URI matches multiple public keys, refusing.");

        if (n_certificates > 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                        "Provided URI matches multiple certificates, refusing.");

        if (n_certificates != 0) {
                _cleanup_(X509_freep) X509 *cert = NULL;
                r = pkcs11_token_read_x509_certificate(m, session, certificate, &cert);
                if (r < 0)
                        return r;

                pkey = X509_get_pubkey(cert);
                if (!pkey)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to extract public key from X.509 certificate.");
        } else {
                r = pkcs11_token_read_public_key(m, session, public_key, &pkey);
                if (r < 0)
                        return r;
        }

        /* Let's read some random data off the token and write it to the kernel pool before we generate our
         * random key from it. This way we can claim the quality of the RNG is at least as good as the
         * kernel's and the token's pool */
        (void) pkcs11_token_acquire_rng(m, session);

        data->pin_used = TAKE_PTR(pin_used);
        data->pkey = TAKE_PTR(pkey);
        return 0;
}

int pkcs11_acquire_public_key(
                const char *uri,
                const char *askpw_friendly_name,
                const char *askpw_icon_name,
                EVP_PKEY **ret_pkey,
                char **ret_pin_used) {

        _cleanup_(pkcs11_acquire_public_key_callback_data_release) struct pkcs11_acquire_public_key_callback_data data = {
                .askpw_friendly_name = askpw_friendly_name,
                .askpw_icon_name = askpw_icon_name,
        };
        int r;

        assert(uri);
        assert(ret_pkey);

        r = pkcs11_find_token(uri, pkcs11_acquire_public_key_callback, &data);
        if (r == -EAGAIN) /* pkcs11_find_token() doesn't log about this error, but all others */
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Specified PKCS#11 token with URI '%s' not found.",
                                       uri);
        if (r < 0)
                return r;

        *ret_pkey = TAKE_PTR(data.pkey);
        if (ret_pin_used)
                *ret_pin_used = TAKE_PTR(data.pin_used);
        return 0;
}
#endif

static int list_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        _cleanup_free_ char *token_uri_string = NULL, *token_label = NULL, *token_manufacturer_id = NULL, *token_model = NULL;
        _cleanup_(sym_p11_kit_uri_freep) P11KitUri *token_uri = NULL;
        Table *t = userdata;
        int uri_result, r;

        assert(slot_info);
        assert(token_info);

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        /* We only care about hardware devices here with a token inserted. Let's filter everything else
         * out. (Note that the user can explicitly specify non-hardware tokens if they like, but during
         * enumeration we'll filter those, since software tokens are typically the system certificate store
         * and such, and it's typically not what people want to bind their home directories to.) */
        if (!FLAGS_SET(slot_info->flags, CKF_HW_SLOT|CKF_TOKEN_PRESENT))
                return -EAGAIN;

        token_label = pkcs11_token_label(token_info);
        if (!token_label)
                return log_oom();

        token_manufacturer_id = pkcs11_token_manufacturer_id(token_info);
        if (!token_manufacturer_id)
                return log_oom();

        token_model = pkcs11_token_model(token_info);
        if (!token_model)
                return log_oom();

        token_uri = uri_from_token_info(token_info);
        if (!token_uri)
                return log_oom();

        uri_result = sym_p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, &token_uri_string);
        if (uri_result != P11_KIT_URI_OK)
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Failed to format slot URI: %s", sym_p11_kit_uri_message(uri_result));

        r = table_add_many(
                        t,
                        TABLE_STRING, token_uri_string,
                        TABLE_STRING, token_label,
                        TABLE_STRING, token_manufacturer_id,
                        TABLE_STRING, token_model);
        if (r < 0)
                return table_log_add_error(r);

        return -EAGAIN; /* keep scanning */
}
#endif

int pkcs11_list_tokens(void) {
#if HAVE_P11KIT
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("uri", "label", "manufacturer", "model");
        if (!t)
                return log_oom();

        r = pkcs11_find_token(NULL, list_callback, t);
        if (r < 0 && r != -EAGAIN)
                return r;

        if (table_isempty(t)) {
                log_info("No suitable PKCS#11 tokens found.");
                return 0;
        }

        r = table_print(t, stdout);
        if (r < 0)
                return log_error_errno(r, "Failed to show device table: %m");

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PKCS#11 tokens not supported on this build.");
#endif
}

#if HAVE_P11KIT
static int auto_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        _cleanup_(sym_p11_kit_uri_freep) P11KitUri *token_uri = NULL;
        char **t = userdata;
        int uri_result, r;

        assert(slot_info);
        assert(token_info);

        r = dlopen_p11kit();
        if (r < 0)
                return r;

        if (!FLAGS_SET(token_info->flags, CKF_HW_SLOT|CKF_TOKEN_PRESENT))
                return -EAGAIN;

        if (*t)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                       "More than one suitable PKCS#11 token found.");

        token_uri = uri_from_token_info(token_info);
        if (!token_uri)
                return log_oom();

        uri_result = sym_p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, t);
        if (uri_result != P11_KIT_URI_OK)
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Failed to format slot URI: %s", sym_p11_kit_uri_message(uri_result));

        return 0;
}
#endif

int pkcs11_find_token_auto(char **ret) {
#if HAVE_P11KIT
        int r;

        r = pkcs11_find_token(NULL, auto_callback, ret);
        if (r == -EAGAIN)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "No suitable PKCS#11 tokens found.");
        if (r < 0)
                return r;

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PKCS#11 tokens not supported on this build.");
#endif
}

#if HAVE_P11KIT
void pkcs11_crypt_device_callback_data_release(pkcs11_crypt_device_callback_data *data) {
        erase_and_free(data->decrypted_key);

        if (data->free_encrypted_key)
                free(data->encrypted_key);
}

int pkcs11_crypt_device_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        pkcs11_crypt_device_callback_data *data = ASSERT_PTR(userdata);
        CK_OBJECT_HANDLE object;
        int r;

        assert(m);
        assert(slot_info);
        assert(token_info);
        assert(uri);

        /* Called for every token matching our URI */

        r = pkcs11_token_login(
                        m,
                        session,
                        slot_id,
                        token_info,
                        data->friendly_name,
                        "drive-harddisk",
                        "pkcs11-pin",
                        "cryptsetup.pkcs11-pin",
                        data->until,
                        data->askpw_flags,
                        data->headless,
                        NULL);
        if (r < 0)
                return r;

        /* We are likely called during early boot, where entropy is scarce. Mix some data from the PKCS#11
         * token, if it supports that. It should be cheap, given that we already are talking to it anyway and
         * shouldn't hurt. */
        (void) pkcs11_token_acquire_rng(m, session);

        r = pkcs11_token_find_private_key(m, session, uri, &object);
        if (r < 0)
                return r;

        r = pkcs11_token_decrypt_data(
                        m,
                        session,
                        object,
                        data->encrypted_key,
                        data->encrypted_key_size,
                        &data->decrypted_key,
                        &data->decrypted_key_size);
        if (r < 0)
                return r;

        return 0;
}
#endif
