/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !ENABLE_DNS_OVER_TLS || !DNS_OVER_TLS_USE_GNUTLS
#error This source file requires DNS-over-TLS to be enabled and GnuTLS to be available.
#endif

#include <gnutls/socket.h>

#include "iovec-util.h"
#include "resolved-dns-stream.h"
#include "resolved-dnstls.h"
#include "resolved-manager.h"

#define TLS_PROTOCOL_PRIORITY "NORMAL:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2"
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(gnutls_session_t, gnutls_deinit, NULL);

static ssize_t dnstls_stream_vec_push(gnutls_transport_ptr_t p, const giovec_t *iov, int iovcnt) {
        int r;

        assert(p);

        r = dns_stream_writev((DnsStream*) p, (const struct iovec*) iov, iovcnt, DNS_STREAM_WRITE_TLS_DATA);
        if (r < 0) {
                errno = -r;
                return -1;
        }

        return r;
}

int dnstls_stream_connect_tls(DnsStream *stream, DnsServer *server) {
        _cleanup_(gnutls_deinitp) gnutls_session_t gs = NULL;
        int r;

        assert(stream);
        assert(server);

        r = gnutls_init(&gs, GNUTLS_CLIENT | GNUTLS_ENABLE_FALSE_START | GNUTLS_NONBLOCK);
        if (r < 0)
                return r;

        /* As DNS-over-TLS is a recent protocol, older TLS versions can be disabled */
        r = gnutls_priority_set_direct(gs, TLS_PROTOCOL_PRIORITY, NULL);
        if (r < 0)
                return r;

        r = gnutls_credentials_set(gs, GNUTLS_CRD_CERTIFICATE, stream->manager->dnstls_data.cert_cred);
        if (r < 0)
                return r;

        if (server->dnstls_data.session_data.size > 0) {
                gnutls_session_set_data(gs, server->dnstls_data.session_data.data, server->dnstls_data.session_data.size);

                // Clear old session ticket
                gnutls_free(server->dnstls_data.session_data.data);
                server->dnstls_data.session_data.data = NULL;
                server->dnstls_data.session_data.size = 0;
        }

        if (server->manager->dns_over_tls_mode == DNS_OVER_TLS_YES) {
                if (server->server_name)
                        gnutls_session_set_verify_cert(gs, server->server_name, 0);
                else {
                        stream->dnstls_data.validation.type = GNUTLS_DT_IP_ADDRESS;
                        if (server->family == AF_INET) {
                                stream->dnstls_data.validation.data = (unsigned char*) &server->address.in.s_addr;
                                stream->dnstls_data.validation.size = 4;
                        } else {
                                stream->dnstls_data.validation.data = server->address.in6.s6_addr;
                                stream->dnstls_data.validation.size = 16;
                        }
                        gnutls_session_set_verify_cert2(gs, &stream->dnstls_data.validation, 1, 0);
                }
        }

        if (server->server_name) {
                r = gnutls_server_name_set(gs, GNUTLS_NAME_DNS, server->server_name, strlen(server->server_name));
                if (r < 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set server name: %s", gnutls_strerror(r));
        }

        gnutls_handshake_set_timeout(gs, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        gnutls_transport_set_ptr2(gs, (gnutls_transport_ptr_t) (long) stream->fd, stream);
        gnutls_transport_set_vec_push_function(gs, &dnstls_stream_vec_push);

        stream->encrypted = true;
        stream->dnstls_data.handshake = gnutls_handshake(gs);
        if (stream->dnstls_data.handshake < 0 && gnutls_error_is_fatal(stream->dnstls_data.handshake))
                return -ECONNREFUSED;

        stream->dnstls_data.session = TAKE_PTR(gs);

        return 0;
}

void dnstls_stream_free(DnsStream *stream) {
        assert(stream);
        assert(stream->encrypted);

        if (stream->dnstls_data.session)
                gnutls_deinit(stream->dnstls_data.session);
}

int dnstls_stream_on_io(DnsStream *stream, uint32_t revents) {
        int r;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.session);

        if (stream->dnstls_data.shutdown) {
                r = gnutls_bye(stream->dnstls_data.session, GNUTLS_SHUT_RDWR);
                if (r == GNUTLS_E_AGAIN) {
                        stream->dnstls_events = gnutls_record_get_direction(stream->dnstls_data.session) == 1 ? EPOLLOUT : EPOLLIN;
                        return -EAGAIN;
                } else if (r < 0)
                        log_debug("Failed to invoke gnutls_bye: %s", gnutls_strerror(r));

                stream->dnstls_events = 0;
                stream->dnstls_data.shutdown = false;
                dns_stream_unref(stream);
                return DNSTLS_STREAM_CLOSED;
        } else if (stream->dnstls_data.handshake < 0) {
                stream->dnstls_data.handshake = gnutls_handshake(stream->dnstls_data.session);
                if (stream->dnstls_data.handshake == GNUTLS_E_AGAIN) {
                        stream->dnstls_events = gnutls_record_get_direction(stream->dnstls_data.session) == 1 ? EPOLLOUT : EPOLLIN;
                        return -EAGAIN;
                } else if (stream->dnstls_data.handshake < 0) {
                        log_debug("Failed to invoke gnutls_handshake: %s", gnutls_strerror(stream->dnstls_data.handshake));
                        if (gnutls_error_is_fatal(stream->dnstls_data.handshake))
                                return -ECONNREFUSED;
                }

                stream->dnstls_events = 0;
        }

        return 0;
}

int dnstls_stream_shutdown(DnsStream *stream, int error) {
        int r;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.session);

        /* Store TLS Ticket for faster successive TLS handshakes */
        if (stream->server && stream->server->dnstls_data.session_data.size == 0 && stream->dnstls_data.handshake == GNUTLS_E_SUCCESS)
                gnutls_session_get_data2(stream->dnstls_data.session, &stream->server->dnstls_data.session_data);

        if (IN_SET(error, ETIMEDOUT, 0)) {
                r = gnutls_bye(stream->dnstls_data.session, GNUTLS_SHUT_RDWR);
                if (r == GNUTLS_E_AGAIN) {
                        if (!stream->dnstls_data.shutdown) {
                                stream->dnstls_data.shutdown = true;
                                dns_stream_ref(stream);
                                return -EAGAIN;
                        }
                } else if (r < 0)
                        log_debug("Failed to invoke gnutls_bye: %s", gnutls_strerror(r));
        }

        return 0;
}

ssize_t dnstls_stream_writev(DnsStream *stream, const struct iovec *iov, size_t iovcnt) {
        ssize_t ss;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.session);
        assert(iov);
        assert(iovec_total_size(iov, iovcnt) > 0);

        gnutls_record_cork(stream->dnstls_data.session);

        for (size_t i = 0; i < iovcnt; i++) {
                ss = gnutls_record_send(
                        stream->dnstls_data.session,
                        iov[i].iov_base, iov[i].iov_len);
                if (ss < 0)
                        break;
        }

        ss = gnutls_record_uncork(stream->dnstls_data.session, 0);
        if (ss < 0)
                switch (ss) {
                case GNUTLS_E_INTERRUPTED:
                        return -EINTR;
                case GNUTLS_E_AGAIN:
                        return -EAGAIN;
                default:
                        return log_debug_errno(SYNTHETIC_ERRNO(EPIPE),
                                               "Failed to invoke gnutls_record_send: %s",
                                               gnutls_strerror(ss));
                }

        return ss;
}

ssize_t dnstls_stream_read(DnsStream *stream, void *buf, size_t count) {
        ssize_t ss;

        assert(stream);
        assert(stream->encrypted);
        assert(stream->dnstls_data.session);
        assert(buf);

        ss = gnutls_record_recv(stream->dnstls_data.session, buf, count);
        if (ss < 0)
                switch (ss) {
                case GNUTLS_E_INTERRUPTED:
                        return -EINTR;
                case GNUTLS_E_AGAIN:
                        return -EAGAIN;
                default:
                        return log_debug_errno(SYNTHETIC_ERRNO(EPIPE),
                                               "Failed to invoke gnutls_record_recv: %s",
                                               gnutls_strerror(ss));
                }

        return ss;
}

void dnstls_server_free(DnsServer *server) {
        assert(server);

        if (server->dnstls_data.session_data.data)
                gnutls_free(server->dnstls_data.session_data.data);
}

int dnstls_manager_init(Manager *manager) {
        int r;
        assert(manager);

        r = gnutls_certificate_allocate_credentials(&manager->dnstls_data.cert_cred);
        if (r < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                         "Failed to allocate SSL credentials: %s",
                                         gnutls_strerror(r));

        r = gnutls_certificate_set_x509_system_trust(manager->dnstls_data.cert_cred);
        if (r < 0)
                log_warning("Failed to load system trust store: %s", gnutls_strerror(r));

        return 0;
}

void dnstls_manager_free(Manager *manager) {
        assert(manager);

        if (manager->dnstls_data.cert_cred)
                gnutls_certificate_free_credentials(manager->dnstls_data.cert_cred);
}
