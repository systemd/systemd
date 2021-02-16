/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#if HAVE_P11KIT
#  include <p11-kit/p11-kit.h>
#  include <p11-kit/uri.h>
#endif

#include "macro.h"
#include "openssl-util.h"
#include "time-util.h"

bool pkcs11_uri_valid(const char *uri);

#if HAVE_P11KIT
int uri_from_string(const char *p, P11KitUri **ret);

P11KitUri *uri_from_module_info(const CK_INFO *info);
P11KitUri *uri_from_slot_info(const CK_SLOT_INFO *slot_info);
P11KitUri *uri_from_token_info(const CK_TOKEN_INFO *token_info);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(P11KitUri*, p11_kit_uri_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(CK_FUNCTION_LIST**, p11_kit_modules_finalize_and_release, NULL);

CK_RV pkcs11_get_slot_list_malloc(CK_FUNCTION_LIST *m, CK_SLOT_ID **ret_slotids, CK_ULONG *ret_n_slotids);

char *pkcs11_token_label(const CK_TOKEN_INFO *token_info);
char *pkcs11_token_manufacturer_id(const CK_TOKEN_INFO *token_info);
char *pkcs11_token_model(const CK_TOKEN_INFO *token_info);

int pkcs11_token_login(CK_FUNCTION_LIST *m, CK_SESSION_HANDLE session, CK_SLOT_ID slotid, const CK_TOKEN_INFO *token_info, const char *friendly_name, const char *icon_name, const char *keyname, usec_t until, char **ret_used_pin);

int pkcs11_token_find_x509_certificate(CK_FUNCTION_LIST *m, CK_SESSION_HANDLE session, P11KitUri *search_uri, CK_OBJECT_HANDLE *ret_object);
#if HAVE_OPENSSL
int pkcs11_token_read_x509_certificate(CK_FUNCTION_LIST *m, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, X509 **ret_cert);
#endif

int pkcs11_token_find_private_key(CK_FUNCTION_LIST *m, CK_SESSION_HANDLE session, P11KitUri *search_uri, CK_OBJECT_HANDLE *ret_object);
int pkcs11_token_decrypt_data(CK_FUNCTION_LIST *m, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, const void *encrypted_data, size_t encrypted_data_size, void **ret_decrypted_data, size_t *ret_decrypted_data_size);

int pkcs11_token_acquire_rng(CK_FUNCTION_LIST *m, CK_SESSION_HANDLE session);

typedef int (*pkcs11_find_token_callback_t)(CK_FUNCTION_LIST *m, CK_SESSION_HANDLE session, CK_SLOT_ID slotid, const CK_SLOT_INFO *slot_info, const CK_TOKEN_INFO *token_info, P11KitUri *uri, void *userdata);
int pkcs11_find_token(const char *pkcs11_uri, pkcs11_find_token_callback_t callback, void *userdata);

#if HAVE_OPENSSL
int pkcs11_acquire_certificate(const char *uri, const char *askpw_friendly_name, const char *askpw_icon_name, X509 **ret_cert, char **ret_pin_used);
#endif

#endif

int pkcs11_list_tokens(void);
int pkcs11_find_token_auto(char **ret);
