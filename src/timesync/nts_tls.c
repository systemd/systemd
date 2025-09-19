/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <assert.h>

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#else
#include <openssl/ssl.h>
#endif

#include "nts.h"

int NTS_TLS_extract_keys(
                NTS_TLS *opaque,
                NTS_AEADAlgorithmType aead,
                uint8_t *c2s,
                uint8_t *s2c,
                int key_capacity) {

        assert(opaque);
        assert(c2s);
        assert(s2c);

#ifdef USE_GNUTLS
        gnutls_session_t session = (void *)opaque;
#else
        SSL *session = (void *)opaque;
#endif

        uint8_t *keys[] = { c2s, s2c };
        const char label[] = "EXPORTER-network-time-security";

        const struct NTS_AEADParam *info = NTS_get_param(aead);
        if (!info)
                return -3;
        else if (info->key_size > key_capacity)
                return -2;

        for (int i=0; i < 2; i++) {
                const char context[5] = { 0, 0, (aead >> 8) & 0xFF, aead & 0xFF, i };
#ifdef USE_GNUTLS
                if (gnutls_prf_rfc5705(
                                        session,
                                        strlen(label), label,
                                        sizeof(context), context,
                                        info->key_size,
                                        (char *)keys[i]
                                ) != GNUTLS_E_SUCCESS)
#else
                if (SSL_export_keying_material(
                                        session,
                                        keys[i], info->key_size,
                                        label, strlen(label),
                                        (uint8_t *)context, sizeof context, 1)
                                != 1)
#endif
                        return -1;
        }

        return 0;
}

int NTS_TLS_handshake(NTS_TLS *opaque) {
        assert(opaque);
#ifdef USE_GNUTLS
        gnutls_session_t session = (void *)opaque;

        int result = gnutls_handshake(session);
        if (result == GNUTLS_E_SUCCESS)
                return 0;
        else
                return gnutls_error_is_fatal(result)? -1 : 1;
#else
        SSL *session = (void *)opaque;

        int result = SSL_connect(session);
        if (result == 1)
                return 0;

        switch (SSL_get_error(session, result)) {
        case SSL_ERROR_ZERO_RETURN:
                return 0;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
                return 1;
        default:
                return -1;
        }
#endif
}

ssize_t NTS_TLS_write(NTS_TLS *opaque, const void *buffer, size_t size) {
        assert(opaque);
        assert(buffer);

#ifdef USE_GNUTLS
        gnutls_session_t session = (void *)opaque;
        ssize_t result = gnutls_record_send(session, buffer, size);
        return result > 0? result : -!!gnutls_error_is_fatal(result);
#else
        SSL *session = (void *)opaque;
        int result = SSL_write(session, buffer, size);
        if (result > 0)
                return result;

        switch (SSL_get_error(session, result)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
                return 0;
        default:
                return -1;
        }
#endif
}

ssize_t NTS_TLS_read(NTS_TLS *opaque, void *buffer, size_t size) {
        assert(opaque);
        assert(buffer);

#ifdef USE_GNUTLS
        gnutls_session_t session = (void *)opaque;
        ssize_t result = gnutls_record_recv(session, buffer, size);
        return result > 0? result : -!!gnutls_error_is_fatal(result);
#else
        SSL *session = (void *)opaque;
        int result = SSL_read(session, buffer, size);
        if (result > 0)
                return result;

        switch (SSL_get_error(session, result)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
                return 0;
        default:
                return -1;
        }
#endif
}

void NTS_TLS_close(NTS_TLS *opaque) {
        assert(opaque);

#ifdef USE_GNUTLS
        gnutls_session_t session = (void *)opaque;

        /* unidirectional closing is enough */
        (void) gnutls_bye(session, GNUTLS_SHUT_WR);

        void *certs = NULL;
        int r = gnutls_credentials_get(session, GNUTLS_CRD_CERTIFICATE, &certs);
        assert(r == GNUTLS_E_SUCCESS);
        (void) r;

        int sock = gnutls_transport_get_int(session);
        gnutls_deinit(session);
        gnutls_certificate_free_credentials(certs);
        close(sock);
#else
        SSL *session = (void *)opaque;

        /* unidirectional closing is enough */
        (void) SSL_shutdown(session);
        SSL_free(session);
#endif
}

#define CHECK(what) if(what); else goto CLEANUP;
#define CLEANUP exit

#ifdef USE_GNUTLS

NTS_TLS* NTS_TLS_setup(
                const char *hostname,
                int socket) {

        assert(hostname);

        gnutls_certificate_credentials_t certs = NULL;
        gnutls_session_t tls = NULL;
        CHECK(gnutls_certificate_allocate_credentials(&certs) == GNUTLS_E_SUCCESS);
        #undef CLEANUP
        #define CLEANUP ctx_cleanup

        CHECK(gnutls_init(&tls, GNUTLS_CLIENT) == GNUTLS_E_SUCCESS);
        #undef CLEANUP
        #define CLEANUP sess_cleanup

        CHECK(gnutls_certificate_set_x509_system_trust(certs) > 0);
        CHECK(gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, certs) == GNUTLS_E_SUCCESS);

        CHECK(gnutls_priority_set_direct(tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3", NULL) == GNUTLS_E_SUCCESS);
        gnutls_session_set_verify_cert(tls, hostname, 0);

        CHECK(gnutls_server_name_set(tls, GNUTLS_NAME_DNS, hostname, strlen(hostname)) == GNUTLS_E_SUCCESS);

        unsigned char alpn[] = "ntske/1";
        CHECK(
                gnutls_alpn_set_protocols(
                        tls,
                        &(gnutls_datum_t){ .data = alpn, .size = strlen((char*)alpn) },
                        1,
                        GNUTLS_ALPN_MANDATORY
                ) == GNUTLS_E_SUCCESS
        );

        gnutls_transport_set_int(tls, socket);
        gnutls_handshake_set_timeout(tls, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        return (void *)tls;

sess_cleanup:
        gnutls_deinit(tls);
ctx_cleanup:
        gnutls_certificate_free_credentials(certs);
exit:
        return NULL;
}
#undef CLEANUP

#else

NTS_TLS* NTS_TLS_setup(
                const char *hostname,
                int socket) {

        assert(hostname);

        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        CHECK(ctx);
        #undef CLEANUP
        #define CLEANUP ctx_cleanup

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        CHECK(SSL_CTX_set_default_verify_paths(ctx) == 1);
        CHECK(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1);

        SSL *tls = SSL_new(ctx);
        CHECK(tls);
        #undef CLEANUP
        #define CLEANUP sess_cleanup

        CHECK(SSL_set1_host(tls, hostname) == 1);
        CHECK(SSL_set_tlsext_host_name(tls, hostname) == 1);

        unsigned char alpn[] = "\x07ntske/1";
        CHECK(SSL_set_alpn_protos(tls, alpn, strlen((char*)alpn)) == 0);

        BIO *bio = BIO_new(BIO_s_socket());
        CHECK(bio);
        BIO_set_fd(bio, socket, BIO_CLOSE);
        SSL_set_bio(tls, bio, bio);

        SSL_CTX_free(ctx);
        return (void *)tls;

sess_cleanup:
        SSL_free(tls);
ctx_cleanup:
        SSL_CTX_free(ctx);
exit:
        return NULL;
}
#endif
