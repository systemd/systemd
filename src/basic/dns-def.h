/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

/* Length of a single label, with all escaping removed, excluding any trailing dot or NUL byte */
#define DNS_LABEL_MAX 63

/* Worst case length of a single label, with all escaping applied and room for a trailing NUL byte. */
#define DNS_LABEL_ESCAPED_MAX (DNS_LABEL_MAX*4+1)

/* Maximum length of a full hostname, consisting of a series of unescaped labels, and no trailing dot or NUL byte */
#define DNS_HOSTNAME_MAX 253

/* Maximum length of a full hostname, on the wire, including the final NUL byte */
#define DNS_WIRE_FORMAT_HOSTNAME_MAX 255

/* Maximum number of labels per valid hostname */
#define DNS_N_LABELS_MAX 127

/* RFC 1035 § 4.1.4 name compression: the two high bits tag a 16-bit field as a pointer, the
 * remaining 14 bits carry the offset, which is hence also the last position a name a pointer can
 * reference may start at. */
#define DNS_COMPRESSION_POINTER_FLAG UINT16_C(0xC000)
#define DNS_COMPRESSION_OFFSET_MAX UINT16_C(0x3FFF)
assert_cc((DNS_COMPRESSION_POINTER_FLAG & DNS_COMPRESSION_OFFSET_MAX) == 0);
assert_cc((DNS_COMPRESSION_POINTER_FLAG | DNS_COMPRESSION_OFFSET_MAX) == UINT16_MAX);
/* The tag is the top two bits, which is what lets a reader take it from the first octet alone. */
assert_cc((DNS_COMPRESSION_POINTER_FLAG & UINT16_C(0xFF)) == 0);
