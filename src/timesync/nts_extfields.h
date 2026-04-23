/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */
#pragma once

#include "nts.h"

typedef struct NTS_Query {
        NTS_Cookie cookie;
        const uint8_t *c2s_key, *s2c_key;
        NTS_AEADParam cipher;
        uint8_t extra_cookies;
} NTS_Query;

typedef struct NTS_Receipt {
        NTS_Identifier *identifier;
        NTS_Cookie new_cookie[8];
} NTS_Receipt;

/* Render NTP extension fields in the provided buffer based on the configuration in the NTS struct.
 * The identifier must point to a buffer that will hold a generated unique identifier upon success.
 *
 * RETURNS
 *      The amount of data encoded in bytes (including NTP packet size).
 *      A negative result indicates an error (in which case the contents of uniq_ident are unspecified)
 */
int NTS_add_extension_fields(
                uint8_t dest[static NTS_MAX_PACKET_SIZE],
                const NTS_Query *nts,
                NTS_Identifier *identifier);

/* Processed the NTP extension fields in the provided buffer based on the configuration in the NTS struct,
 * and make this information available in the NTS_Receipt struct.
 *
 * RETURNS
 *      The amount of data processed in bytes (including the NTP packet size).
 *      A negative result indicates an error.
 */
int NTS_parse_extension_fields(
                uint8_t src[static NTS_MAX_PACKET_SIZE],
                size_t src_len,
                const NTS_Query *nts,
                NTS_Receipt *fields);
