/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if ENABLE_DNS_OVER_TLS

#if !HAVE_OPENSSL
#error This source file requires OpenSSL to be available.
#endif

#include "resolved-forward.h"

typedef struct DnsTlsManagerData {
        SSL_CTX *ctx;
} DnsTlsManagerData;

/* Per-server TLS state, kept by the transport using TLS towards the server */
typedef struct DnsTlsServerData {
        SSL_SESSION *session;
        /* Whether the server certificate was verified when 'session' was negotiated */
        bool session_verified;
} DnsTlsServerData;

typedef struct DnsTlsStreamData {
        int handshake;
        bool shutdown;
        bool verify;
        SSL *ssl;
        BUF_MEM *write_buffer;
        size_t buffer_offset;

        /* Where to store the session for resumption when the stream is shut down. Must remain valid while
         * the stream exists. May be NULL. */
        DnsTlsServerData *server_data;
} DnsTlsStreamData;

#define DNSTLS_STREAM_CLOSED 1

int dnstls_stream_connect_tls(
                DnsStream *stream,
                const char *server_name,
                int family,
                const union in_addr_union *address,
                bool verify,
                DnsTlsServerData *server_data);
void dnstls_stream_free(DnsStream *stream);
int dnstls_stream_on_io(DnsStream *stream, uint32_t revents);
int dnstls_stream_shutdown(DnsStream *stream, int error);
ssize_t dnstls_stream_writev(DnsStream *stream, const struct iovec *iov, size_t iovcnt);
ssize_t dnstls_stream_read(DnsStream *stream, void *buf, size_t count);

void dnstls_server_data_done(DnsTlsServerData *d);

int dnstls_manager_init(Manager *manager);
void dnstls_manager_free(Manager *manager);

#endif /* ENABLE_DNS_OVER_TLS */
