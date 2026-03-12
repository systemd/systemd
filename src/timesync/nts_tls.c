/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */

#include <assert.h>
#include <openssl/ssl.h>
#include <string.h>
#include <unistd.h>

#include "nts.h"
#include "ssl-util.h"
#include "timesyncd-forward.h"

int NTS_TLS_extract_keys(
                NTS_TLS *session,
                NTS_AEADAlgorithmType aead,
                uint8_t *c2s,
                uint8_t *s2c,
                int key_capacity) {

        assert(session);
        assert(c2s);
        assert(s2c);

        SSL *tls = (void *)session;

        uint8_t *keys[] = { c2s, s2c };
        const char label[] = "EXPORTER-network-time-security";

        const struct NTS_AEADParam *info = NTS_get_param(aead);
        if (!info)
                return -EINVAL;
        else if (info->key_size > key_capacity)
                return -ENOBUFS;

        for (int i=0; i < 2; i++) {
                const uint8_t context[5] = { 0, 0, (aead >> 8) & 0xFF, aead & 0xFF, i };
                if (SSL_export_keying_material(
                                        tls,
                                        keys[i], info->key_size,
                                        label, strlen(label),
                                        context, sizeof context, 1)
                                != 1)
                        return -EBADE;
        }

        return 0;
}

int NTS_TLS_handshake(NTS_TLS *session) {
        assert(session);
        SSL *tls = (void *)session;

        int result = SSL_connect(tls);
        if (result == 1)
                return 1;

        switch (SSL_get_error(tls, result)) {
        case SSL_ERROR_ZERO_RETURN:
                return -ECONNRESET;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
                return 0;
        default:
                return -EIO;
        }
}

ssize_t NTS_TLS_write(NTS_TLS *session, const void *buffer, size_t size) {
        assert(session);
        assert(buffer);

        SSL *tls = (void *)session;
        int result = SSL_write(tls, buffer, size);
        if (result > 0)
                return result;

        switch (SSL_get_error(tls, result)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
                return 0;
        default:
                return -EIO;
        }
}

ssize_t NTS_TLS_read(NTS_TLS *session, void *buffer, size_t size) {
        assert(session);
        assert(buffer);

        SSL *tls = (void *)session;
        int result = SSL_read(tls, buffer, size);
        if (result > 0)
                return result;

        switch (SSL_get_error(tls, result)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
                return 0;
        default:
                return -EIO;
        }
}

void NTS_TLS_close(NTS_TLS **session) {
        assert(session);
        if (*session == NULL)
                return;

        SSL *tls = (SSL*) *session;
        *session = NULL;

        /* unidirectional closing is enough */
        (void) SSL_shutdown(tls);
        SSL_free(tls);
}

NTS_TLS* NTS_TLS_setup(
                const char *hostname,
                int socket) {

        int r;

        assert(hostname);

        _cleanup_(SSL_CTX_freep) SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx)
                return NULL;

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        r = SSL_CTX_set_default_verify_paths(ctx);
        if (r != 1)
                return NULL;

        r = SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        if (r != 1)
                return NULL;

        _cleanup_(SSL_freep) SSL *tls = SSL_new(ctx);
        if (!tls)
                return NULL;

        r = SSL_set1_host(tls, hostname);
        if (r != 1)
                return NULL;

        r = SSL_set_tlsext_host_name(tls, hostname);
        if (r != 1)
                return NULL;

        unsigned char alpn[] = "\x07ntske/1";
        r = SSL_set_alpn_protos(tls, alpn, strlen((char*)alpn));
        if (r != 0)
                return NULL;

        BIO *bio = BIO_new(BIO_s_socket());
        if (!bio)
                return NULL;

        BIO_set_fd(bio, socket, BIO_NOCLOSE);
        SSL_set_bio(tls, bio, bio);

        /* move the initialized session object to the caller */
        NTS_TLS *ret_ptr = (void *)tls;
        tls = NULL;

        return ret_ptr;
}
