/* SPDX-License-Identifier: LGPL-2.1+ */

#if !ENABLE_DNS_OVER_TLS || !DNS_OVER_TLS_USE_OPENSSL
#error This source file requires DNS-over-TLS to be enabled and OpenSSL to be available.
#endif

#include "resolved-dnstls.h"
#include "resolved-dns-stream.h"

#include <openssl/bio.h>
#include <openssl/err.h>

DEFINE_TRIVIAL_CLEANUP_FUNC(SSL*, SSL_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(BIO*, BIO_free);

int dnstls_stream_connect_tls(DnsStream *stream, DnsServer *server) {
        _cleanup_(SSL_freep) SSL *s = NULL;
        _cleanup_(BIO_freep) BIO *b = NULL;

        assert(stream);
        assert(server);

        b = BIO_new_socket(stream->fd, 0);
        if (!b)
                return -ENOMEM;

        s = SSL_new(server->dnstls_data.ctx);
        if (!s)
                return -ENOMEM;

        SSL_set_connect_state(s);
        SSL_set_bio(s, b, b);
        b = NULL;

        /* DNS-over-TLS using OpenSSL doesn't support TCP Fast Open yet */
        connect(stream->fd, &stream->tfo_address.sa, stream->tfo_salen);
        stream->tfo_salen = 0;

        stream->encrypted = true;
        stream->dnstls_events = EPOLLOUT;
        stream->dnstls_data.ssl = TAKE_PTR(s);

        return 0;
}

void dnstls_stream_free(DnsStream *stream) {
        assert(stream);
        assert(stream->encrypted);

        if (stream->dnstls_data.ssl)
                SSL_free(stream->dnstls_data.ssl);
}

int dnstls_stream_on_io(DnsStream *stream) {
        int r;
        int error;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.ssl);

        if (stream->dnstls_data.shutdown) {
                r = SSL_shutdown(stream->dnstls_data.ssl);
                if (r == 0)
                        return -EAGAIN;
                else if (r < 0) {
                        error = SSL_get_error(stream->dnstls_data.ssl, r);
                        if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                                stream->dnstls_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                                return -EAGAIN;
                        } else {
                                char errbuf[256];

                                ERR_error_string_n(error, errbuf, sizeof(errbuf));
                                log_debug("Failed to invoke SSL_shutdown: %s", errbuf);
                        }
                }

                stream->dnstls_events = 0;
                stream->dnstls_data.shutdown = false;
                dns_stream_unref(stream);
                return DNSTLS_STREAM_CLOSED;
        } else if (stream->dnstls_data.handshake <= 0) {
                stream->dnstls_data.handshake = SSL_do_handshake(stream->dnstls_data.ssl);
                if (stream->dnstls_data.handshake <= 0) {
                        error = SSL_get_error(stream->dnstls_data.ssl, stream->dnstls_data.handshake);
                        if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                                stream->dnstls_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                                return -EAGAIN;
                        } else {
                                char errbuf[256];

                                ERR_error_string_n(error, errbuf, sizeof(errbuf));
                                log_debug("Failed to invoke SSL_do_handshake: %s", errbuf);
                                return -ECONNREFUSED;
                        }
                }

                stream->dnstls_events = 0;
        }

        return 0;
}

int dnstls_stream_shutdown(DnsStream *stream, int error) {
        int r;
        int ssl_error;
        SSL_SESSION *s;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.ssl);

        if (error == ETIMEDOUT) {
                r = SSL_shutdown(stream->dnstls_data.ssl);
                if (r == 0) {
                        if (!stream->dnstls_data.shutdown) {
                                stream->dnstls_data.shutdown = true;
                                dns_stream_ref(stream);
                        }
                        return -EAGAIN;
                } else if (r < 0) {
                        ssl_error = SSL_get_error(stream->dnstls_data.ssl, r);
                        if (IN_SET(ssl_error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                                stream->dnstls_events = ssl_error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                                if (!stream->dnstls_data.shutdown) {
                                        stream->dnstls_data.shutdown = true;
                                        dns_stream_ref(stream);
                                }
                                return -EAGAIN;
                        } else {
                                char errbuf[256];

                                ERR_error_string_n(ssl_error, errbuf, sizeof(errbuf));
                                log_debug("Failed to invoke SSL_shutdown: %s", errbuf);
                        }
                }
        }

        return 0;
}

ssize_t dnstls_stream_write(DnsStream *stream, const char *buf, size_t count) {
        int r;
        int error;
        ssize_t ss;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.ssl);
        assert(buf);

        ss = r = SSL_write(stream->dnstls_data.ssl, buf, count);
        if (r <= 0) {
                error = SSL_get_error(stream->dnstls_data.ssl, ss);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        stream->dnstls_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                        ss = -EAGAIN;
                } else {
                        char errbuf[256];

                        ERR_error_string_n(error, errbuf, sizeof(errbuf));
                        log_debug("Failed to invoke SSL_read: %s", errbuf);
                        ss = -EPIPE;
                }
        }

        stream->dnstls_events = 0;
        return ss;
}

ssize_t dnstls_stream_read(DnsStream *stream, void *buf, size_t count) {
        int r;
        int error;
        ssize_t ss;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.ssl);
        assert(buf);

        ss = r = SSL_read(stream->dnstls_data.ssl, buf, count);
        if (r <= 0) {
                error = SSL_get_error(stream->dnstls_data.ssl, ss);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        stream->dnstls_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                        ss = -EAGAIN;
                } else {
                        char errbuf[256];

                        ERR_error_string_n(error, errbuf, sizeof(errbuf));
                        log_debug("Failed to invoke SSL_read: %s", errbuf);
                        ss = -EPIPE;
                }
        }

        stream->dnstls_events = 0;
        return ss;
}

void dnstls_server_init(DnsServer *server) {
        assert(server);

        server->dnstls_data.ctx = SSL_CTX_new(TLS_client_method());
        if (server->dnstls_data.ctx) {
                SSL_CTX_set_min_proto_version(server->dnstls_data.ctx, TLS1_2_VERSION);
                SSL_CTX_set_options(server->dnstls_data.ctx, SSL_OP_NO_COMPRESSION);
        }
}

void dnstls_server_free(DnsServer *server) {
        assert(server);

        if (server->dnstls_data.ctx)
                SSL_CTX_free(server->dnstls_data.ctx);
}
