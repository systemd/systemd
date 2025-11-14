/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

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

        SSL *session = (void *)opaque;

        uint8_t *keys[] = { c2s, s2c };
        const char label[] = "EXPORTER-network-time-security";

        const struct NTS_AEADParam *info = NTS_get_param(aead);
        if (!info)
                return -3;
        else if (info->key_size > key_capacity)
                return -2;

        for (int i=0; i < 2; i++) {
                const uint8_t context[5] = { 0, 0, (aead >> 8) & 0xFF, aead & 0xFF, i };
                if (SSL_export_keying_material(
                                        session,
                                        keys[i], info->key_size,
                                        label, strlen(label),
                                        context, sizeof context, 1)
                                != 1)
                        return -1;
        }

        return 0;
}

int NTS_TLS_handshake(NTS_TLS *opaque) {
        assert(opaque);
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
}

ssize_t NTS_TLS_write(NTS_TLS *opaque, const void *buffer, size_t size) {
        assert(opaque);
        assert(buffer);

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
}

ssize_t NTS_TLS_read(NTS_TLS *opaque, void *buffer, size_t size) {
        assert(opaque);
        assert(buffer);

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
}

void NTS_TLS_close(NTS_TLS *opaque) {
        assert(opaque);

        SSL *session = (void *)opaque;

        /* unidirectional closing is enough */
        (void) SSL_shutdown(session);
        SSL_free(session);
}

#define CHECK(what) if(what); else goto CLEANUP;
#define CLEANUP exit

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
        BIO_set_fd(bio, socket, BIO_NOCLOSE);
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
