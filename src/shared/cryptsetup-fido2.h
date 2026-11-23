/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "forward.h"
#include "libfido2-util.h"

/* The fields of a "systemd-fido2" LUKS2 token */
typedef struct Fido2Luks2Token {
        struct iovec cid;
        struct iovec salt;
        char *rp_id;
        Fido2EnrollFlags required;
} Fido2Luks2Token;

void fido2_luks2_token_done(Fido2Luks2Token *t);
int fido2_luks2_token_parse(sd_json_variant *v, Fido2Luks2Token *ret);

int acquire_fido2_key(
                const char *volume_name,
                const char *friendly_name,
                const char *device,
                const char *rp_id,
                const void *cid,
                size_t cid_size,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const struct iovec *key_data,
                usec_t until,
                Fido2EnrollFlags required,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size);

int acquire_fido2_key_auto(
                struct crypt_device *cd,
                const char *name,
                const char *friendly_name,
                const char *fido2_device,
                usec_t until,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size);
