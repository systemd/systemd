
/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !ENABLE_DNS_OVER_HTTPS
#error This source file requires DNS-over-HTTPS to be enabled and OpenSSL to be available.
#endif

#include "llhttp.h"

#define MAX_URL_LENGTH 2048

/* Response parts we care */
typedef enum HeaderFields {
        SERVER,
        BODY,
} HeaderFields;

typedef struct {
        const char *at;
        size_t len;
} http_header;

int dnshttps_stream_extract_dns(DnsStream *s);
int dnshttps_packet_to_base64url(DnsTransaction *t);
