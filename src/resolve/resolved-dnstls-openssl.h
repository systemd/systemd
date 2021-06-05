/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !ENABLE_DNS_OVER_TLS || !DNS_OVER_TLS_USE_OPENSSL
#error This source file requires DNS-over-TLS to be enabled and OpenSSL to be available.
#endif

#include <openssl/ssl.h>
#include <stdbool.h>

struct DnsTlsManagerData {
        SSL_CTX *ctx;
};

struct DnsTlsServerData {
        SSL_SESSION *session;
};

struct DnsTlsStreamData {
        int handshake;
        bool shutdown;
        SSL *ssl;
        BUF_MEM *write_buffer;
        size_t buffer_offset;
};
