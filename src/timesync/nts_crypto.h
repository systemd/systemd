/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "nts.h"
#include "nts_extfields.h"

typedef struct AssociatedData {
        const uint8_t *data;
        const size_t length;
} AssociatedData;

/* encrypt the data in ptxt of ptxt_len bytes, and write it to ctxt, using the selected cryptoscheme and key
 * the associated data should point to an array of NULL-terminated chunks of associated data
 *
 * caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block
 *
 * RETURNS: the number of bytes in the ciphertext (< 0 indicates an error)
 */
int NTS_encrypt(uint8_t *ctxt,
                const uint8_t *ptxt,
                int ptxt_len,
                const AssociatedData *,
                const struct NTS_AEADParam *,
                const uint8_t *key);

/* decrypt the data in ctxt of ctxt_len bytes, and write it to ptxt, using the selected cryptoscheme and key
 *
 * the associated data should point to an array of NULL-terminated chunks of associated data
 *
 * caller should make sure that there is enough room in ptxt for holding the decrypted ciphertext;
 * the size of the plaintext will always be less than or equal to the ciphertext ptxt
 *
 * RETURNS: the number of bytes in the decrypted plaintext (< 0 indicates an error)
 */
int NTS_decrypt(uint8_t *ptxt,
                const uint8_t *ctxt,
                int ctxt_len,
                const AssociatedData *,
                const struct NTS_AEADParam *,
                const uint8_t *key);
