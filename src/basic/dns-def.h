/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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
