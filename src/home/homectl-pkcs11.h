/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int identity_add_token_pin(sd_json_variant **v, const char *pin);
int identity_add_pkcs11_key_data(sd_json_variant **v, const char *token_uri);

int list_pkcs11_tokens(void);
int find_pkcs11_token_auto(char **ret);
