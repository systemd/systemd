/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */

#include <assert.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "crypto-util.h"
#include "nts.h"
#include "ssl-util.h"
#include "timesyncd-forward.h"

int NTS_TLS_extract_keys(
                NTS_TLS *session,
                NTS_AEADAlgorithmType aead,
                uint8_t *ret_c2s,
                uint8_t *ret_s2c,
                size_t key_capacity) {

        assert(session);
        assert(ret_c2s);
        assert(ret_s2c);

        SSL *tls = (void *)session;

        uint8_t *keys[] = { ret_c2s, ret_s2c };
        const char label[] = "EXPORTER-network-time-security";

        const NTS_AEADParam *info = NTS_get_param(aead);
        if (!info)
                return -EINVAL;
        else if (info->key_size > key_capacity)
                return -ENOBUFS;

        for (int i=0; i < 2; i++) {
                const uint8_t context[5] = { 0, 0, (aead >> 8) & 0xFF, aead & 0xFF, i };
                if (sym_SSL_export_keying_material(
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

        int result = sym_SSL_connect(tls);
        if (result == 1)
                return 1;

        switch (sym_SSL_get_error(tls, result)) {
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

        /* clamp size to fit in the range required by OpenSSL */
        size = MIN(size, (size_t)INT_MAX);

        SSL *tls = (void *)session;
        int result = sym_SSL_write(tls, buffer, size);
        if (result > 0)
                return result;

        switch (sym_SSL_get_error(tls, result)) {
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

        /* clamp size to fit in the range required by OpenSSL */
        size = MIN(size, (size_t)INT_MAX);

        SSL *tls = (void *)session;
        int result = sym_SSL_read(tls, buffer, size);
        if (result > 0)
                return result;

        switch (sym_SSL_get_error(tls, result)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
                return 0;
        default:
                return -EIO;
        }
}

NTS_TLS* NTS_TLS_free(NTS_TLS *session) {
        if (session == NULL)
                return NULL;

        SSL *tls = (SSL*) session;

        /* unidirectional closing is enough */
        (void) sym_SSL_shutdown(tls);
        sym_SSL_free(tls);

        return NULL;
}

NTS_TLS* NTS_TLS_setup(
                const char *hostname,
                int socket) {

        int r;

        r = dlopen_libssl(LOG_ERR);
        if (r < 0)
                return NULL;

        assert(hostname);

        _cleanup_(SSL_CTX_freep) SSL_CTX *ctx = sym_SSL_CTX_new(sym_TLS_client_method());
        if (!ctx)
                return NULL;

        r = sym_SSL_CTX_set_default_verify_paths(ctx);
        if (r != 1)
                return NULL;

        r = sym_SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        if (r != 1)
                return NULL;

        _cleanup_(SSL_freep) SSL *tls = sym_SSL_new(ctx);
        if (!tls)
                return NULL;

        sym_SSL_set_verify(tls, SSL_VERIFY_PEER, NULL);
        r = sym_SSL_set1_host(tls, hostname);
        if (r != 1)
                return NULL;

        r = sym_SSL_set_tlsext_host_name(tls, hostname);
        if (r != 1)
                return NULL;

        unsigned char alpn[] = "\x07ntske/1";
        r = sym_SSL_set_alpn_protos(tls, alpn, strlen((char*)alpn));
        if (r != 0)
                return NULL;

        BIO *bio = sym_BIO_new(sym_BIO_s_socket());
        if (!bio)
                return NULL;

        sym_BIO_set_fd(bio, socket, BIO_NOCLOSE);
        sym_SSL_set_bio(tls, bio, bio);

        /* move the initialized session object to the caller */
        NTS_TLS *ret_ptr = (void *)tls;
        tls = NULL;

        return ret_ptr;
}
