/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if ENABLE_DNS_OVER_TLS

#if !HAVE_OPENSSL
#error This source file requires OpenSSL to be available.
#endif

#include <openssl/ssl.h>

#include "resolved-forward.h"

typedef struct DnsTlsManagerData {
        SSL_CTX *ctx;
} DnsTlsManagerData;

typedef struct DnsTlsServerData {
        SSL_SESSION *session;
} DnsTlsServerData;

typedef struct DnsTlsStreamData {
        int handshake;
        bool shutdown;
        SSL *ssl;
        BUF_MEM *write_buffer;
        size_t buffer_offset;
} DnsTlsStreamData;

#define DNSTLS_STREAM_CLOSED 1

int dnstls_stream_connect_tls(DnsStream *stream, DnsServer *server);
void dnstls_stream_free(DnsStream *stream);
int dnstls_stream_on_io(DnsStream *stream, uint32_t revents);
int dnstls_stream_shutdown(DnsStream *stream, int error);
ssize_t dnstls_stream_writev(DnsStream *stream, const struct iovec *iov, size_t iovcnt);
ssize_t dnstls_stream_read(DnsStream *stream, void *buf, size_t count);

void dnstls_server_free(DnsServer *server);

int dnstls_manager_init(Manager *manager);
void dnstls_manager_free(Manager *manager);

#endif /* ENABLE_DNS_OVER_TLS */
