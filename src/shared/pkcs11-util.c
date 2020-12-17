/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "ask-password-api.h"
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

        if (!in_charset(p, ALPHANUMERICAL "-_?;&%="))
                return false;

        return true;
}

#if HAVE_P11KIT

int uri_from_string(const char *p, P11KitUri **ret) {
        _cleanup_(p11_kit_uri_freep) P11KitUri *uri = NULL;

        assert(p);
        assert(ret);

        uri = p11_kit_uri_new();
        if (!uri)
                return -ENOMEM;

        if (p11_kit_uri_parse(p, P11_KIT_URI_FOR_ANY, uri) != P11_KIT_URI_OK)
                return -EINVAL;

        *ret = TAKE_PTR(uri);
        return 0;
}

P11KitUri *uri_from_module_info(const CK_INFO *info) {
        P11KitUri *uri;

        assert(info);

        uri = p11_kit_uri_new();
        if (!uri)
                return NULL;

        *p11_kit_uri_get_module_info(uri) = *info;
        return uri;
}

P11KitUri *uri_from_slot_info(const CK_SLOT_INFO *slot_info) {
        P11KitUri *uri;

        assert(slot_info);

        uri = p11_kit_uri_new();
        if (!uri)
                return NULL;

        *p11_kit_uri_get_slot_info(uri) = *slot_info;
        return uri;
}

P11KitUri *uri_from_token_info(const CK_TOKEN_INFO *token_info) {
        P11KitUri *uri;

        assert(token_info);

        uri = p11_kit_uri_new();
        if (!uri)
                return NULL;

        *p11_kit_uri_get_token_info(uri) = *token_info;
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

int pkcs11_token_login(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slotid,
                const CK_TOKEN_INFO *token_info,
                const char *friendly_name,
                const char *icon_name,
                const char *keyname,
                usec_t until,
                char **ret_used_pin) {

        _cleanup_free_ char *token_uri_string = NULL, *token_uri_escaped = NULL, *id = NULL, *token_label = NULL;
        _cleanup_(p11_kit_uri_freep) P11KitUri *token_uri = NULL;
        CK_TOKEN_INFO updated_token_info;
        int uri_result, r;
        CK_RV rv;

        assert(m);
        assert(token_info);

        token_label = pkcs11_token_label(token_info);
        if (!token_label)
                return log_oom();

        token_uri = uri_from_token_info(token_info);
        if (!token_uri)
                return log_oom();

        uri_result = p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, &token_uri_string);
        if (uri_result != P11_KIT_URI_OK)
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Failed to format slot URI: %s", p11_kit_uri_message(uri_result));

        if (FLAGS_SET(token_info->flags, CKF_PROTECTED_AUTHENTICATION_PATH)) {
                rv = m->C_Login(session, CKU_USER, NULL, 0);
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to log into security token '%s': %s", token_label, p11_kit_strerror(rv));

                log_info("Successfully logged into security token '%s' via protected authentication path.", token_label);
                if (ret_used_pin)
                        *ret_used_pin = NULL;
                return 0;
        }

        if (!FLAGS_SET(token_info->flags, CKF_LOGIN_REQUIRED)) {
                log_info("No login into security token '%s' required.", token_label);
                if (ret_used_pin)
                        *ret_used_pin = NULL;
                return 0;
        }

        token_uri_escaped = cescape(token_uri_string);
        if (!token_uri_escaped)
                return log_oom();

        id = strjoin("pkcs11:", token_uri_escaped);
        if (!id)
                return log_oom();

        for (unsigned tries = 0; tries < 3; tries++) {
                _cleanup_strv_free_erase_ char **passwords = NULL;
                char **i, *e;

                e = getenv("PIN");
                if (e) {
                        passwords = strv_new(e);
                        if (!passwords)
                                return log_oom();

                        string_erase(e);
                        if (unsetenv("PIN") < 0)
                                return log_error_errno(errno, "Failed to unset $PIN: %m");
                } else {
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
                        r = ask_password_auto(text, icon_name, id, keyname, until, 0, &passwords);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query PIN for security token '%s': %m", token_label);
                }

                STRV_FOREACH(i, passwords) {
                        rv = m->C_Login(session, CKU_USER, (CK_UTF8CHAR*) *i, strlen(*i));
                        if (rv == CKR_OK)  {

                                if (ret_used_pin) {
                                        char *c;

                                        c = strdup(*i);
                                        if (!c)
                                                return log_oom();

                                        *ret_used_pin = c;
                                }

                                log_info("Successfully logged into security token '%s'.", token_label);
                                return 0;
                        }
                        if (rv == CKR_PIN_LOCKED)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "PIN has been locked, please reset PIN of security token '%s'.", token_label);
                        if (!IN_SET(rv, CKR_PIN_INCORRECT, CKR_PIN_LEN_RANGE))
                                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                                       "Failed to log into security token '%s': %s", token_label, p11_kit_strerror(rv));

                        /* Referesh the token info, so that we can prompt knowing the new flags if they changed. */
                        rv = m->C_GetTokenInfo(slotid, &updated_token_info);
                        if (rv != CKR_OK)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                                       "Failed to acquire updated security token information for slot %lu: %s",
                                                       slotid, p11_kit_strerror(rv));

                        token_info = &updated_token_info;
                        log_notice("PIN for token '%s' is incorrect, please try again.", token_label);
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

        assert(m);
        assert(search_uri);
        assert(ret_object);

        attributes = p11_kit_uri_get_attributes(search_uri, &n_attributes);
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
                                       "Failed to initialize object find call: %s", p11_kit_strerror(rv));

        rv = m->C_FindObjects(session, objects, ELEMENTSOF(objects), &n_objects);
        rv2 = m->C_FindObjectsFinal(session);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to find objects: %s", p11_kit_strerror(rv));
        if (rv2 != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to finalize object find call: %s", p11_kit_strerror(rv));
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

        rv = m->C_GetAttributeValue(session, object, &attribute, 1);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to read X.509 certificate size off token: %s", p11_kit_strerror(rv));

        buffer = malloc(attribute.ulValueLen);
        if (!buffer)
                return log_oom();

        attribute.pValue = buffer;

        rv = m->C_GetAttributeValue(session, object, &attribute, 1);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to read X.509 certificate data off token: %s", p11_kit_strerror(rv));

        p = attribute.pValue;
        x509 = d2i_X509(NULL, &p, attribute.ulValueLen);
        if (!x509)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed parse X.509 certificate.");

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

        bool found_decrypt = false, found_class = false, found_key_type = false;
        _cleanup_free_ CK_ATTRIBUTE *attributes_buffer = NULL;
        CK_ULONG n_attributes, a, n_objects;
        CK_ATTRIBUTE *attributes = NULL;
        CK_OBJECT_HANDLE objects[2];
        CK_RV rv, rv2;

        assert(m);
        assert(search_uri);
        assert(ret_object);

        attributes = p11_kit_uri_get_attributes(search_uri, &n_attributes);
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
                        if (c != CKO_PRIVATE_KEY)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Selected PKCS#11 object is not a private key, refusing.");

                        found_class = true;
                        break;
                }

                case CKA_DECRYPT: {
                        CK_BBOOL b;

                        if (attributes[a].ulValueLen != sizeof(b))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid PKCS#11 CKA_DECRYPT attribute size.");

                        memcpy(&b, attributes[a].pValue, sizeof(b));
                        if (!b)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Selected PKCS#11 object is not suitable for decryption, refusing.");

                        found_decrypt = true;
                        break;
                }

                case CKA_KEY_TYPE: {
                        CK_KEY_TYPE t;

                        if (attributes[a].ulValueLen != sizeof(t))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid PKCS#11 CKA_KEY_TYPE attribute size.");

                        memcpy(&t, attributes[a].pValue, sizeof(t));
                        if (t != CKK_RSA)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected PKCS#11 object is not an RSA key, refusing.");

                        found_key_type = true;
                        break;
                }}
        }

        if (!found_decrypt || !found_class || !found_key_type) {
                /* Hmm, let's slightly extend the attribute list we search for */

                attributes_buffer = new(CK_ATTRIBUTE, n_attributes + !found_decrypt + !found_class + !found_key_type);
                if (!attributes_buffer)
                        return log_oom();

                memcpy(attributes_buffer, attributes, sizeof(CK_ATTRIBUTE) * n_attributes);

                if (!found_decrypt) {
                        static const CK_BBOOL yes = true;

                        attributes_buffer[n_attributes++] = (CK_ATTRIBUTE) {
                                .type = CKA_DECRYPT,
                                .pValue = (CK_BBOOL*) &yes,
                                .ulValueLen = sizeof(yes),
                        };
                }

                if (!found_class) {
                        static const CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;

                        attributes_buffer[n_attributes++] = (CK_ATTRIBUTE) {
                                .type = CKA_CLASS,
                                .pValue = (CK_OBJECT_CLASS*) &class,
                                .ulValueLen = sizeof(class),
                        };
                }

                if (!found_key_type) {
                        static const CK_KEY_TYPE type = CKK_RSA;

                        attributes_buffer[n_attributes++] = (CK_ATTRIBUTE) {
                                .type = CKA_KEY_TYPE,
                                .pValue = (CK_KEY_TYPE*) &type,
                                .ulValueLen = sizeof(type),
                        };
                }

                attributes = attributes_buffer;
        }

        rv = m->C_FindObjectsInit(session, attributes, n_attributes);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to initialize object find call: %s", p11_kit_strerror(rv));

        rv = m->C_FindObjects(session, objects, ELEMENTSOF(objects), &n_objects);
        rv2 = m->C_FindObjectsFinal(session);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to find objects: %s", p11_kit_strerror(rv));
        if (rv2 != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to finalize object find call: %s", p11_kit_strerror(rv));
        if (n_objects == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Failed to find selected private key suitable for decryption on token.");
        if (n_objects > 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                       "Configured private key URI matches multiple keys, refusing.");

        *ret_object = objects[0];
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

        static const CK_MECHANISM mechanism = {
                 .mechanism = CKM_RSA_PKCS
        };
        _cleanup_(erase_and_freep) CK_BYTE *dbuffer = NULL;
        CK_ULONG dbuffer_size = 0;
        CK_RV rv;

        assert(m);
        assert(encrypted_data);
        assert(encrypted_data_size > 0);
        assert(ret_decrypted_data);
        assert(ret_decrypted_data_size);

        rv = m->C_DecryptInit(session, (CK_MECHANISM*) &mechanism, object);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to initialize decryption on security token: %s", p11_kit_strerror(rv));

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
                                       "Failed to decrypt key on security token: %s", p11_kit_strerror(rv));

        log_info("Successfully decrypted key with security token.");

        *ret_decrypted_data = TAKE_PTR(dbuffer);
        *ret_decrypted_data_size = dbuffer_size;
        return 0;
}

int pkcs11_token_acquire_rng(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session) {

        _cleanup_free_ void *buffer = NULL;
        size_t rps;
        CK_RV rv;
        int r;

        assert(m);

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
                                       "Failed to generate RNG data on security token: %s", p11_kit_strerror(rv));

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
                                       "Failed to create session for security token '%s': %s", token_label, p11_kit_strerror(rv));

        if (callback)
                r = callback(m, session, slotid, slot_info, token_info, search_uri, userdata);
        else
                r = 1; /* if not callback was specified, just say we found what we were looking for */

        rv = m->C_CloseSession(session);
        if (rv != CKR_OK)
                log_warning("Failed to close session on PKCS#11 token, ignoring: %s", p11_kit_strerror(rv));

        return r;
}

static int slot_process(
                CK_FUNCTION_LIST *m,
                CK_SLOT_ID slotid,
                P11KitUri *search_uri,
                pkcs11_find_token_callback_t callback,
                void *userdata) {

        _cleanup_(p11_kit_uri_freep) P11KitUri* slot_uri = NULL, *token_uri = NULL;
        _cleanup_free_ char *token_uri_string = NULL;
        CK_TOKEN_INFO token_info;
        CK_SLOT_INFO slot_info;
        int uri_result;
        CK_RV rv;

        assert(m);

        /* We return -EAGAIN for all failures we can attribute to a specific slot in some way, so that the
         * caller might try other slots before giving up. */

        rv = m->C_GetSlotInfo(slotid, &slot_info);
        if (rv != CKR_OK) {
                log_warning("Failed to acquire slot info for slot %lu, ignoring slot: %s", slotid, p11_kit_strerror(rv));
                return -EAGAIN;
        }

        slot_uri = uri_from_slot_info(&slot_info);
        if (!slot_uri)
                return log_oom();

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *slot_uri_string = NULL;

                uri_result = p11_kit_uri_format(slot_uri, P11_KIT_URI_FOR_ANY, &slot_uri_string);
                if (uri_result != P11_KIT_URI_OK) {
                        log_warning("Failed to format slot URI, ignoring slot: %s", p11_kit_uri_message(uri_result));
                        return -EAGAIN;
                }

                log_debug("Found slot with URI %s", slot_uri_string);
        }

        rv = m->C_GetTokenInfo(slotid, &token_info);
        if (rv == CKR_TOKEN_NOT_PRESENT) {
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "Token not present in slot, ignoring.");
        } else if (rv != CKR_OK) {
                log_warning("Failed to acquire token info for slot %lu, ignoring slot: %s", slotid, p11_kit_strerror(rv));
                return -EAGAIN;
        }

        token_uri = uri_from_token_info(&token_info);
        if (!token_uri)
                return log_oom();

        uri_result = p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, &token_uri_string);
        if (uri_result != P11_KIT_URI_OK) {
                log_warning("Failed to format slot URI: %s", p11_kit_uri_message(uri_result));
                return -EAGAIN;
        }

        if (search_uri && !p11_kit_uri_match_token_info(search_uri, &token_info))
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

        _cleanup_free_ char *name = NULL, *module_uri_string = NULL;
        _cleanup_(p11_kit_uri_freep) P11KitUri* module_uri = NULL;
        _cleanup_free_ CK_SLOT_ID *slotids = NULL;
        CK_ULONG n_slotids = 0;
        int uri_result;
        CK_INFO info;
        size_t k;
        CK_RV rv;
        int r;

        assert(m);

        /* We ignore most errors from modules here, in order to skip over faulty modules: one faulty module
         * should not have the effect that we don't try the others anymore. We indicate such per-module
         * failures with -EAGAIN, which let's the caller try the next module. */

        name = p11_kit_module_get_name(m);
        if (!name)
                return log_oom();

        log_debug("Trying PKCS#11 module %s.", name);

        rv = m->C_GetInfo(&info);
        if (rv != CKR_OK) {
                log_warning("Failed to get info on PKCS#11 module, ignoring module: %s", p11_kit_strerror(rv));
                return -EAGAIN;
        }

        module_uri = uri_from_module_info(&info);
        if (!module_uri)
                return log_oom();

        uri_result = p11_kit_uri_format(module_uri, P11_KIT_URI_FOR_ANY, &module_uri_string);
        if (uri_result != P11_KIT_URI_OK) {
                log_warning("Failed to format module URI, ignoring module: %s", p11_kit_uri_message(uri_result));
                return -EAGAIN;
        }

        log_debug("Found module with URI %s", module_uri_string);

        rv = pkcs11_get_slot_list_malloc(m, &slotids, &n_slotids);
        if (rv != CKR_OK) {
                log_warning("Failed to get slot list, ignoring module: %s", p11_kit_strerror(rv));
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

        _cleanup_(p11_kit_modules_finalize_and_releasep) CK_FUNCTION_LIST **modules = NULL;
        _cleanup_(p11_kit_uri_freep) P11KitUri *search_uri = NULL;
        int r;

        /* Execute the specified callback for each matching token found. If nothing is found returns
         * -EAGAIN. Logs about all errors, except for EAGAIN, which the caller has to log about. */

        if (pkcs11_uri) {
                r = uri_from_string(pkcs11_uri, &search_uri);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse PKCS#11 URI '%s': %m", pkcs11_uri);
        }

        modules = p11_kit_modules_load_and_initialize(0);
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
struct pkcs11_acquire_certificate_callback_data {
        char *pin_used;
        X509 *cert;
        const char *askpw_friendly_name, *askpw_icon_name;
};

static void pkcs11_acquire_certificate_callback_data_release(struct pkcs11_acquire_certificate_callback_data *data) {
        erase_and_free(data->pin_used);
        X509_free(data->cert);
}

static int pkcs11_acquire_certificate_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        _cleanup_(erase_and_freep) char *pin_used = NULL;
        struct pkcs11_acquire_certificate_callback_data *data = userdata;
        CK_OBJECT_HANDLE object;
        int r;

        assert(m);
        assert(slot_info);
        assert(token_info);
        assert(uri);
        assert(data);

        /* Called for every token matching our URI */

        r = pkcs11_token_login(m, session, slot_id, token_info, data->askpw_friendly_name, data->askpw_icon_name, "pkcs11-pin", UINT64_MAX, &pin_used);
        if (r < 0)
                return r;

        r = pkcs11_token_find_x509_certificate(m, session, uri, &object);
        if (r < 0)
                return r;

        r = pkcs11_token_read_x509_certificate(m, session, object, &data->cert);
        if (r < 0)
                return r;

        /* Let's read some random data off the token and write it to the kernel pool before we generate our
         * random key from it. This way we can claim the quality of the RNG is at least as good as the
         * kernel's and the token's pool */
        (void) pkcs11_token_acquire_rng(m, session);

        data->pin_used = TAKE_PTR(pin_used);
        return 1;
}

int pkcs11_acquire_certificate(
                const char *uri,
                const char *askpw_friendly_name,
                const char *askpw_icon_name,
                X509 **ret_cert,
                char **ret_pin_used) {

        _cleanup_(pkcs11_acquire_certificate_callback_data_release) struct pkcs11_acquire_certificate_callback_data data = {
                .askpw_friendly_name = askpw_friendly_name,
                .askpw_icon_name = askpw_icon_name,
        };
        int r;

        assert(uri);
        assert(ret_cert);

        r = pkcs11_find_token(uri, pkcs11_acquire_certificate_callback, &data);
        if (r == -EAGAIN) /* pkcs11_find_token() doesn't log about this error, but all others */
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Specified PKCS#11 token with URI '%s' not found.",
                                       uri);
        if (r < 0)
                return r;

        *ret_cert = TAKE_PTR(data.cert);

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
        _cleanup_(p11_kit_uri_freep) P11KitUri *token_uri = NULL;
        Table *t = userdata;
        int uri_result, r;

        assert(slot_info);
        assert(token_info);

        /* We only care about hardware devices here with a token inserted. Let's filter everything else
         * out. (Note that the user can explicitly specify non-hardware tokens if they like, but during
         * enumeration we'll filter those, since software tokens are typically the system certificate store
         * and such, and it's typically not what people want to bind their home directories to.) */
        if (!FLAGS_SET(token_info->flags, CKF_HW_SLOT|CKF_TOKEN_PRESENT))
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

        uri_result = p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, &token_uri_string);
        if (uri_result != P11_KIT_URI_OK)
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Failed to format slot URI: %s", p11_kit_uri_message(uri_result));

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

        if (table_get_rows(t) <= 1) {
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

        _cleanup_(p11_kit_uri_freep) P11KitUri *token_uri = NULL;
        char **t = userdata;
        int uri_result;

        assert(slot_info);
        assert(token_info);

        if (!FLAGS_SET(token_info->flags, CKF_HW_SLOT|CKF_TOKEN_PRESENT))
                return -EAGAIN;

        if (*t)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                       "More than one suitable PKCS#11 token found.");

        token_uri = uri_from_token_info(token_info);
        if (!token_uri)
                return log_oom();

        uri_result = p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, t);
        if (uri_result != P11_KIT_URI_OK)
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Failed to format slot URI: %s", p11_kit_uri_message(uri_result));

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
