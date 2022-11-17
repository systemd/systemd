/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !ENABLE_DNS_OVER_TLS || !DNS_OVER_TLS_USE_OPENSSL
#error This source file requires DNS-over-TLS to be enabled and OpenSSL to be available.
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "io-util.h"
#include "openssl-util.h"
#include "resolved-dns-stream.h"
#include "resolved-dnstls.h"
#include "resolved-manager.h"

static char *dnstls_error_string(int ssl_error, char *buf, size_t count) {
        assert(buf || count == 0);
        if (ssl_error == SSL_ERROR_SSL)
                ERR_error_string_n(ERR_get_error(), buf, count);
        else
                snprintf(buf, count, "SSL_get_error()=%d", ssl_error);
        return buf;
}

#define DNSTLS_ERROR_BUFSIZE 256
#define DNSTLS_ERROR_STRING(error) \
        dnstls_error_string((error), (char[DNSTLS_ERROR_BUFSIZE]){}, DNSTLS_ERROR_BUFSIZE)

static int dnstls_flush_write_buffer(DnsStream *stream) {
        ssize_t ss;

        assert(stream);
        assert(stream->encrypted);

        if (stream->dnstls_data.buffer_offset < stream->dnstls_data.write_buffer->length) {
                assert(stream->dnstls_data.write_buffer->data);

                struct iovec iov[1];
                iov[0] = IOVEC_MAKE(stream->dnstls_data.write_buffer->data + stream->dnstls_data.buffer_offset,
                                    stream->dnstls_data.write_buffer->length - stream->dnstls_data.buffer_offset);
                ss = dns_stream_writev(stream, iov, 1, DNS_STREAM_WRITE_TLS_DATA);
                if (ss < 0) {
                        if (ss == -EAGAIN)
                                stream->dnstls_events |= EPOLLOUT;

                        return ss;
                } else {
                        stream->dnstls_data.buffer_offset += ss;

                        if (stream->dnstls_data.buffer_offset < stream->dnstls_data.write_buffer->length) {
                                stream->dnstls_events |= EPOLLOUT;
                                return -EAGAIN;
                        } else {
                                BIO_reset(SSL_get_wbio(stream->dnstls_data.ssl));
                                stream->dnstls_data.buffer_offset = 0;
                        }
                }
        }

        return 0;
}

int dnstls_stream_connect_tls(DnsStream *stream, DnsServer *server) {
        _cleanup_(BIO_freep) BIO *rb = NULL, *wb = NULL;
        _cleanup_(SSL_freep) SSL *s = NULL;
        int error, r;

        assert(stream);
        assert(stream->manager);
        assert(server);

        rb = BIO_new_socket(stream->fd, 0);
        if (!rb)
                return -ENOMEM;

        wb = BIO_new(BIO_s_mem());
        if (!wb)
                return -ENOMEM;

        BIO_get_mem_ptr(wb, &stream->dnstls_data.write_buffer);
        stream->dnstls_data.buffer_offset = 0;

        s = SSL_new(stream->manager->dnstls_data.ctx);
        if (!s)
                return -ENOMEM;

        SSL_set_connect_state(s);
        r = SSL_set_session(s, server->dnstls_data.session);
        if (r == 0)
                return -EIO;
        SSL_set_bio(s, TAKE_PTR(rb), TAKE_PTR(wb));

        if (server->manager->dns_over_tls_mode == DNS_OVER_TLS_YES) {
                X509_VERIFY_PARAM *v;

                SSL_set_verify(s, SSL_VERIFY_PEER, NULL);
                v = SSL_get0_param(s);
                if (server->server_name) {
                        X509_VERIFY_PARAM_set_hostflags(v, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                        if (X509_VERIFY_PARAM_set1_host(v, server->server_name, 0) == 0)
                                return -ECONNREFUSED;
                } else {
                        const unsigned char *ip;
                        ip = server->family == AF_INET ? (const unsigned char*) &server->address.in.s_addr : server->address.in6.s6_addr;
                        if (X509_VERIFY_PARAM_set1_ip(v, ip, FAMILY_ADDRESS_SIZE(server->family)) == 0)
                                return -ECONNREFUSED;
                }
        }

        if (server->server_name) {
                r = SSL_set_tlsext_host_name(s, server->server_name);
                if (r <= 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Failed to set server name: %s", DNSTLS_ERROR_STRING(SSL_ERROR_SSL));
        }

        ERR_clear_error();
        stream->dnstls_data.handshake = SSL_do_handshake(s);
        if (stream->dnstls_data.handshake <= 0) {
                error = SSL_get_error(s, stream->dnstls_data.handshake);
                if (!IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE))
                        return log_debug_errno(SYNTHETIC_ERRNO(ECONNREFUSED),
                                               "Failed to invoke SSL_do_handshake: %s", DNSTLS_ERROR_STRING(error));
        }

        stream->encrypted = true;
        stream->dnstls_data.ssl = TAKE_PTR(s);

        r = dnstls_flush_write_buffer(stream);
        if (r < 0 && r != -EAGAIN) {
                SSL_free(TAKE_PTR(stream->dnstls_data.ssl));
                return r;
        }

        return 0;
}

void dnstls_stream_free(DnsStream *stream) {
        assert(stream);
        assert(stream->encrypted);

        if (stream->dnstls_data.ssl)
                SSL_free(stream->dnstls_data.ssl);
}

int dnstls_stream_on_io(DnsStream *stream, uint32_t revents) {
        int error, r;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.ssl);

        /* Flush write buffer when requested by OpenSSL */
        if ((revents & EPOLLOUT) && (stream->dnstls_events & EPOLLOUT)) {
                r = dnstls_flush_write_buffer(stream);
                if (r < 0)
                        return r;
        }

        if (stream->dnstls_data.shutdown) {
                ERR_clear_error();
                r = SSL_shutdown(stream->dnstls_data.ssl);
                if (r == 0) {
                        stream->dnstls_events = 0;

                        r = dnstls_flush_write_buffer(stream);
                        if (r < 0)
                                return r;

                        return -EAGAIN;
                } else if (r < 0) {
                        error = SSL_get_error(stream->dnstls_data.ssl, r);
                        if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                                stream->dnstls_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;

                                r = dnstls_flush_write_buffer(stream);
                                if (r < 0)
                                        return r;

                                return -EAGAIN;
                        } else if (error == SSL_ERROR_SYSCALL) {
                                if (errno > 0)
                                        log_debug_errno(errno, "Failed to invoke SSL_shutdown, ignoring: %m");
                        } else
                                log_debug("Failed to invoke SSL_shutdown, ignoring: %s", DNSTLS_ERROR_STRING(error));
                }

                stream->dnstls_events = 0;
                stream->dnstls_data.shutdown = false;

                r = dnstls_flush_write_buffer(stream);
                if (r < 0)
                        return r;

                dns_stream_unref(stream);
                return DNSTLS_STREAM_CLOSED;
        } else if (stream->dnstls_data.handshake <= 0) {
                ERR_clear_error();
                stream->dnstls_data.handshake = SSL_do_handshake(stream->dnstls_data.ssl);
                if (stream->dnstls_data.handshake <= 0) {
                        error = SSL_get_error(stream->dnstls_data.ssl, stream->dnstls_data.handshake);
                        if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                                stream->dnstls_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                                r = dnstls_flush_write_buffer(stream);
                                if (r < 0)
                                        return r;

                                return -EAGAIN;
                        } else
                                return log_debug_errno(SYNTHETIC_ERRNO(ECONNREFUSED),
                                                       "Failed to invoke SSL_do_handshake: %s",
                                                       DNSTLS_ERROR_STRING(error));
                }

                stream->dnstls_events = 0;
                r = dnstls_flush_write_buffer(stream);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dnstls_stream_shutdown(DnsStream *stream, int error) {
        int ssl_error, r;
        SSL_SESSION *s;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.ssl);

        if (stream->server) {
                s = SSL_get1_session(stream->dnstls_data.ssl);
                if (s) {
                        if (stream->server->dnstls_data.session)
                                SSL_SESSION_free(stream->server->dnstls_data.session);

                        stream->server->dnstls_data.session = s;
                }
        }

        if (error == ETIMEDOUT) {
                ERR_clear_error();
                r = SSL_shutdown(stream->dnstls_data.ssl);
                if (r == 0) {
                        if (!stream->dnstls_data.shutdown) {
                                stream->dnstls_data.shutdown = true;
                                dns_stream_ref(stream);
                        }

                        stream->dnstls_events = 0;

                        r = dnstls_flush_write_buffer(stream);
                        if (r < 0)
                                return r;

                        return -EAGAIN;
                } else if (r < 0) {
                        ssl_error = SSL_get_error(stream->dnstls_data.ssl, r);
                        if (IN_SET(ssl_error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                                stream->dnstls_events = ssl_error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                                r = dnstls_flush_write_buffer(stream);
                                if (r < 0 && r != -EAGAIN)
                                        return r;

                                if (!stream->dnstls_data.shutdown) {
                                        stream->dnstls_data.shutdown = true;
                                        dns_stream_ref(stream);
                                }
                                return -EAGAIN;
                        } else if (ssl_error == SSL_ERROR_SYSCALL) {
                                if (errno > 0)
                                        log_debug_errno(errno, "Failed to invoke SSL_shutdown, ignoring: %m");
                        } else
                                log_debug("Failed to invoke SSL_shutdown, ignoring: %s", DNSTLS_ERROR_STRING(ssl_error));
                }

                stream->dnstls_events = 0;
                r = dnstls_flush_write_buffer(stream);
                if (r < 0)
                        return r;
        }

        return 0;
}

static ssize_t dnstls_stream_write(DnsStream *stream, const char *buf, size_t count) {
        int error, r;
        ssize_t ss;

        ERR_clear_error();
        ss = r = SSL_write(stream->dnstls_data.ssl, buf, count);
        if (r <= 0) {
                error = SSL_get_error(stream->dnstls_data.ssl, r);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        stream->dnstls_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                        ss = -EAGAIN;
                } else if (error == SSL_ERROR_ZERO_RETURN) {
                        stream->dnstls_events = 0;
                        ss = 0;
                } else {
                        log_debug("Failed to invoke SSL_write: %s", DNSTLS_ERROR_STRING(error));
                        stream->dnstls_events = 0;
                        ss = -EPIPE;
                }
        } else
                stream->dnstls_events = 0;

        r = dnstls_flush_write_buffer(stream);
        if (r < 0)
                return r;

        return ss;
}

ssize_t dnstls_stream_writev(DnsStream *stream, const struct iovec *iov, size_t iovcnt) {
        _cleanup_free_ char *buf = NULL;
        size_t count;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.ssl);
        assert(iov);
        assert(IOVEC_TOTAL_SIZE(iov, iovcnt) > 0);

        if (iovcnt == 1)
                return dnstls_stream_write(stream, iov[0].iov_base, iov[0].iov_len);

        /* As of now, OpenSSL can not accumulate multiple writes, so join into a
           single buffer. Suboptimal, but better than multiple SSL_write calls. */
        count = IOVEC_TOTAL_SIZE(iov, iovcnt);
        buf = new(char, count);
        for (size_t i = 0, pos = 0; i < iovcnt; pos += iov[i].iov_len, i++)
                memcpy(buf + pos, iov[i].iov_base, iov[i].iov_len);

        return dnstls_stream_write(stream, buf, count);
}

ssize_t dnstls_stream_read(DnsStream *stream, void *buf, size_t count) {
        int error, r;
        ssize_t ss;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.ssl);
        assert(buf);

        ERR_clear_error();
        ss = r = SSL_read(stream->dnstls_data.ssl, buf, count);
        if (r <= 0) {
                error = SSL_get_error(stream->dnstls_data.ssl, r);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        /* If we receive SSL_ERROR_WANT_READ here, there are two possible scenarios:
                           * OpenSSL needs to renegotiate (so we want to get an EPOLLIN event), or
                           * There is no more application data is available, so we can just return
                           And apparently there's no nice way to distinguish between the two.
                           To handle this, never set EPOLLIN and just continue as usual.
                           If OpenSSL really wants to read due to renegotiation, it will tell us
                           again on SSL_write (at which point we will request EPOLLIN force a read);
                           or we will just eventually read data anyway while we wait for a packet */
                        stream->dnstls_events = error == SSL_ERROR_WANT_READ ? 0 : EPOLLOUT;
                        ss = -EAGAIN;
                } else if (error == SSL_ERROR_ZERO_RETURN) {
                        stream->dnstls_events = 0;
                        ss = 0;
                } else {
                        log_debug("Failed to invoke SSL_read: %s", DNSTLS_ERROR_STRING(error));
                        stream->dnstls_events = 0;
                        ss = -EPIPE;
                }
        } else
                stream->dnstls_events = 0;

        /* flush write buffer in cache of renegotiation */
        r = dnstls_flush_write_buffer(stream);
        if (r < 0)
                return r;

        return ss;
}

void dnstls_server_free(DnsServer *server) {
        assert(server);

        if (server->dnstls_data.session)
                SSL_SESSION_free(server->dnstls_data.session);
}

int dnstls_manager_init(Manager *manager) {
        int r;

        assert(manager);

        ERR_load_crypto_strings();
        SSL_load_error_strings();

        manager->dnstls_data.ctx = SSL_CTX_new(TLS_client_method());
        if (!manager->dnstls_data.ctx)
                return -ENOMEM;

        r = SSL_CTX_set_min_proto_version(manager->dnstls_data.ctx, TLS1_2_VERSION);
        if (r == 0)
                return -EIO;

        (void) SSL_CTX_set_options(manager->dnstls_data.ctx, SSL_OP_NO_COMPRESSION);

        r = SSL_CTX_set_default_verify_paths(manager->dnstls_data.ctx);
        if (r == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EIO),
                                         "Failed to load system trust store: %s",
                                         ERR_error_string(ERR_get_error(), NULL));

        return 0;
}

void dnstls_manager_free(Manager *manager) {
        assert(manager);

        if (manager->dnstls_data.ctx)
                SSL_CTX_free(manager->dnstls_data.ctx);
}
