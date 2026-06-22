/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "nts.h"
#include "nts_extfields.h"

typedef struct iovec AssociatedData;

/* encrypt the plaintext in ptxt, and write the ciphertext to ctxt, using the selected cryptoscheme and key.
 * the associated data should point to an array of NULL-terminated chunks of associated data
 *
 * caller should make sure that ctxt has enough room for holding the plaintext + one additional block
 *
 * RETURNS: the number of bytes in the ciphertext (< 0 indicates an error)
 */
ssize_t NTS_encrypt(const struct iovec *ctxt,
                const struct iovec *ptxt,
                const AssociatedData *info,
                const NTS_AEADParam *aead,
                const uint8_t *key);

/* decrypt the ciphertext in ctxt, and write the plaintext to ptxt, using the selected cryptoscheme and key.
 * ptxt and ctxt are described by iovecs: iov_base points at the buffer, iov_len gives its size. The iovec
 * structures themselves are not modified (only ptxt's buffer is written to).
 *
 * the associated data should point to an array of NULL-terminated chunks of associated data
 *
 * caller should make sure that ptxt has enough room for holding the decrypted ciphertext;
 * the size of the plaintext will always be less than or equal to the ciphertext size
 *
 * RETURNS: the number of bytes in the decrypted plaintext (< 0 indicates an error)
 */
ssize_t NTS_decrypt(const struct iovec *ptxt,
                const struct iovec *ctxt,
                const AssociatedData *info,
                const NTS_AEADParam *aead,
                const uint8_t *key);
