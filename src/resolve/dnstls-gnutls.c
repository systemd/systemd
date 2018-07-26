/* SPDX-License-Identifier: LGPL-2.1+ */

#if !ENABLE_DNS_OVER_TLS || !HAVE_GNUTLS
#error This source file requires DNS-over-TLS to be enabled and GnuTLS to be available.
#endif

#include "dnstls.h"
#include "resolved-dns-stream.h"

#include <gnutls/gnutls.h>
#include <gnutls/socket.h>

struct DnsTlsServerData {
        gnutls_certificate_credentials_t tls_cert_cred;
        gnutls_datum_t tls_session_data;
};

int dnstls_stream_connect_tls(DnsStream *stream, DnsServer *server) {
        struct DnsTlsServerData *d = server->dnstls_data;
        gnutls_session_t gs;
        int r;

        r = gnutls_init(&gs, GNUTLS_CLIENT | GNUTLS_ENABLE_FALSE_START | GNUTLS_NONBLOCK);
        if (r < 0)
                return r;

        /* As DNS-over-TLS is a recent protocol, older TLS versions can be disabled */
        r = gnutls_priority_set_direct(gs, "NORMAL:-VERS-ALL:+VERS-TLS1.2", NULL);
        if (r < 0)
                return r;

        r = gnutls_credentials_set(gs, GNUTLS_CRD_CERTIFICATE, d->tls_cert_cred);
        if (r < 0)
                return r;

        if (d->tls_session_data.size > 0)
                gnutls_session_set_data(gs, d->tls_session_data.data, d->tls_session_data.size);

        gnutls_handshake_set_timeout(gs, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        gnutls_transport_set_ptr2(gs, (gnutls_transport_ptr_t) (long) stream->fd, stream);
        gnutls_transport_set_vec_push_function(gs, (gnutls_vec_push_func) &dns_stream_tls_writev);

        stream->encrypted = true;
        stream->tls_session = gs;
        stream->tls_handshake = gnutls_handshake(gs);
        if (stream->tls_handshake < 0 && gnutls_error_is_fatal(stream->tls_handshake))
                return -ECONNREFUSED;

        return 0;
}

void dnstls_stream_free(DnsStream *s) {
        if (s->tls_session)
                gnutls_deinit((gnutls_session_t) s->tls_session);
}

int dnstls_stream_handshake(DnsStream *s) {
        if (s->tls_handshake >= 0)
                return 1;

        assert(s->tls_session);

        s->tls_handshake = gnutls_handshake((gnutls_session_t) s->tls_session);
        if (s->tls_handshake < 0)
                return gnutls_error_is_fatal(s->tls_handshake) ? -ECONNREFUSED : 0;

        if (gnutls_session_get_flags((gnutls_session_t) s->tls_session) & GNUTLS_SFLAGS_FALSE_START)
                return -EAGAIN;

        return 1;
}

int dnstls_stream_shutdown(DnsStream *s, int error) {
        int r;

        if (s->tls_session && IN_SET(error, ETIMEDOUT, 0)) {
                r = gnutls_bye((gnutls_session_t) s->tls_session, GNUTLS_SHUT_RDWR);
                if (r == GNUTLS_E_AGAIN && !s->tls_bye) {
                        s->tls_bye = true;
                        return -EAGAIN;
                }
        }
        return 0;
}

int dnstls_stream_shutdown_complete(DnsStream *s) {
        int r;

        if (!s->tls_bye)
                return 1;

        assert(s->tls_session);

        r = gnutls_bye((gnutls_session_t) s->tls_session, GNUTLS_SHUT_RDWR);
        if (r == GNUTLS_E_AGAIN)
                return -EAGAIN;

        s->tls_bye = false;
        return 0;
}

ssize_t dnstls_stream_write(DnsStream *s, const char *buf, size_t count) {
        ssize_t ss;

        ss = gnutls_record_send((gnutls_session_t) s->tls_session, buf, count);
        if (ss < 0) {
                switch(ss) {
                case GNUTLS_E_INTERRUPTED:
                        return -EINTR;
                case GNUTLS_E_AGAIN:
                        return -EAGAIN;
                default:
                        log_debug("Failed to invoke gnutls_record_send: %s", gnutls_strerror(ss));
                        return -EIO;
                }
        }
        return ss;
}

ssize_t dnstls_stream_read(DnsStream *s, void *buf, size_t count) {
        ssize_t ss;

        ss = gnutls_record_recv((gnutls_session_t) s->tls_session, buf, count);
        if (ss < 0) {
                switch(ss) {
                case GNUTLS_E_INTERRUPTED:
                        return -EINTR;
                case GNUTLS_E_AGAIN:
                        return -EAGAIN;
                default:
                        log_debug("Failed to invoke gnutls_record_recv: %s", gnutls_strerror(ss));
                        return -EIO;
                }
        }
        return ss;
}

int dnstls_on_stream_connection(DnsStream *s) {
        /* Store TLS Ticket for faster succesive TLS handshakes */
        if (s->tls_session && s->server) {
                struct DnsTlsServerData *d = s->server->dnstls_data;
                if (d->tls_session_data.data)
                        gnutls_free(d->tls_session_data.data);

                gnutls_session_get_data2(s->tls_session, &d->tls_session_data);
        }
        return 0;
}

void dnstls_server_init(DnsServer *server) {
        struct DnsTlsServerData *d;

        server->dnstls_data = d = new0(struct DnsTlsServerData, 1);

        /* Do not verify cerificate */
        gnutls_certificate_allocate_credentials(&d->tls_cert_cred);
}

void dnstls_server_free(DnsServer *server) {
        struct DnsTlsServerData *d = server->dnstls_data;

        if (d->tls_cert_cred)
                gnutls_certificate_free_credentials(d->tls_cert_cred);

        if (d->tls_session_data.data)
                gnutls_free(d->tls_session_data.data);

        server->dnstls_data = mfree(server->dnstls_data);
}
