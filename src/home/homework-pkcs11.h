/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_P11KIT
#include "homework-forward.h"
#include "pkcs11-util.h"

struct pkcs11_callback_data {
        UserRecord *user_record;
        UserRecord *secret;
        Pkcs11EncryptedKey *encrypted_key;
        char *decrypted_password;
};

void pkcs11_callback_data_release(struct pkcs11_callback_data *data);

int pkcs11_callback(CK_FUNCTION_LIST *m, CK_SESSION_HANDLE session, CK_SLOT_ID slot_id, const CK_SLOT_INFO *slot_info, const CK_TOKEN_INFO *token_info, P11KitUri *uri, void *userdata);
#endif
