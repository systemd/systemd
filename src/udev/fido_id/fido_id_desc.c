/* SPDX-License-Identifier: LGPL-2.1+ */
/* Inspired by Andrew Lutomirski's 'u2f-hidraw-policy.c' */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fido_id_desc.h"

#define HID_RPTDESC_FIRST_BYTE_LONG_ITEM 0xfeu
#define HID_RPTDESC_TYPE_GLOBAL 0x1u
#define HID_RPTDESC_TYPE_LOCAL 0x2u
#define HID_RPTDESC_TAG_USAGE_PAGE 0x0u
#define HID_RPTDESC_TAG_USAGE 0x0u

/*
 * HID usage for FIDO CTAP1 ("U2F") and CTAP2 security tokens.
 * https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-u2f_hid.h-v1.0-ps-20141009.txt
 * https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-discovery
 * https://www.usb.org/sites/default/files/hutrr48.pdf
 */
#define FIDO_FULL_USAGE_CTAPHID 0xf1d00001u

/*
 * Parses a HID report descriptor and identifies FIDO CTAP1 ("U2F")/CTAP2 security tokens based on their
 * declared usage.
 * A positive return value indicates that the report descriptor belongs to a FIDO security token.
 * https://www.usb.org/sites/default/files/documents/hid1_11.pdf (Section 6.2.2)
 */
int is_fido_security_token_desc(const uint8_t *desc, size_t desc_len) {
        uint32_t usage = 0;

        for (size_t pos = 0; pos < desc_len; ) {
                uint8_t tag, type, size_code;
                size_t size;
                uint32_t value;

                /* Report descriptors consists of short items (1-5 bytes) and long items (3-258 bytes). */
                if (desc[pos] == HID_RPTDESC_FIRST_BYTE_LONG_ITEM) {
                        /* No long items are defined in the spec; skip them.
                         * The length of the data in a long item is contained in the byte after the long
                         * item tag. The header consists of three bytes: special long item tag, length,
                         * actual tag. */
                        if (pos + 1 >= desc_len)
                                return -EINVAL;
                        pos += desc[pos + 1] + 3;
                        continue;
                }

                /* The first byte of a short item encodes tag, type and size. */
                tag = desc[pos] >> 4;          /* Bits 7 to 4 */
                type = (desc[pos] >> 2) & 0x3; /* Bits 3 and 2 */
                size_code = desc[pos] & 0x3;   /* Bits 1 and 0 */
                /* Size is coded as follows:
                 * 0 -> 0 bytes, 1 -> 1 byte, 2 -> 2 bytes, 3 -> 4 bytes
                 */
                size = size_code < 3 ? size_code : 4;
                /* Consume header byte. */
                pos++;

                /* Extract the item value coded on size bytes. */
                if (pos + size > desc_len)
                        return -EINVAL;
                value = 0;
                for (size_t i = 0; i < size; i++)
                        value |= (uint32_t) desc[pos + i] << (8 * i);
                /* Consume value bytes. */
                pos += size;

                if (type == HID_RPTDESC_TYPE_GLOBAL && tag == HID_RPTDESC_TAG_USAGE_PAGE) {
                        /* A usage page is a 16 bit value coded on at most 16 bits. */
                        if (size > 2)
                                return -EINVAL;
                        /* A usage page sets the upper 16 bits of a following usage. */
                        usage = (value & 0x0000ffffu) << 16;
                }

                if (type == HID_RPTDESC_TYPE_LOCAL && tag == HID_RPTDESC_TAG_USAGE) {
                        /* A usage is a 32 bit value, but is prepended with the current usage page if
                         * coded on less than 4 bytes (that is, at most 2 bytes). */
                        if (size == 4)
                                usage = value;
                        else
                                usage = (usage & 0xffff0000u) | (value & 0x0000ffffu);
                        if (usage == FIDO_FULL_USAGE_CTAPHID)
                                return 1;
                }
        }

        return 0;
}
