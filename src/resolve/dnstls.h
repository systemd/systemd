/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "resolved-dns-stream.h"
#include "resolved-dns-transaction.h"

#if ENABLE_DNS_OVER_TLS

int dnstls_stream_connect_tls(DnsStream *stream, DnsServer *server);
void dnstls_stream_free(DnsStream *s);
int dnstls_stream_handshake(DnsStream *s);
int dnstls_stream_shutdown(DnsStream *s, int error);
int dnstls_stream_shutdown_complete(DnsStream *s);
ssize_t dnstls_stream_write(DnsStream *s, const char *buf, size_t count);
ssize_t dnstls_stream_read(DnsStream *s, void *buf, size_t count);
int dnstls_on_stream_connection(DnsStream *s);
void dnstls_server_init(DnsServer *server);
void dnstls_server_free(DnsServer *server);

#else /* !ENABLE_DNS_OVER_TLS */

static inline void dnstls_stream_free(DnsStream *s) {}
static inline int dnstls_stream_shutdown(DnsStream *s, int error) { return 0; }
static inline int dnstls_on_stream_connection(DnsStream *s) { return 0; }
static inline void dnstls_server_init(DnsServer *server) {}
static inline void dnstls_server_free(DnsServer *server) {}

#endif
