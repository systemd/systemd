/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"

int identity_add_token_pin(JsonVariant **v, const char *pin);

#if HAVE_P11KIT
int identity_add_pkcs11_key_data(JsonVariant **v, const char *token_uri);
#else
static inline int identity_add_pkcs11_key_data(JsonVariant **v, const char *token_uri) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "PKCS#11 tokens not supported on this build.");
}
#endif

int list_pkcs11_tokens(void);
int find_pkcs11_token_auto(char **ret);
