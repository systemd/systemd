/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#include "alloc-util.h"
#include "in-addr-util.h"
#include "log.h"
#include "openssl-util.h"
#include "random-util.h"
#include "timesyncd-ntske-client.h"
#include "timesyncd-ntske-protocol.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(SSL*, SSL_free);

#define AEAD_AES_SIV_CMAC_256_KEY_SIZE 32

static int ntske_aquire_auth_data(Manager *m, NTSKEPacket *packet) {
        int r;

        assert(m);
        assert(packet);

        m->next_protocol = packet->next_protocol;
        m->aead_algorithm = packet->aead_algorithm;

        m->cookies = mfree(m->cookies);
        m->cookies = TAKE_PTR(packet->cookies);
        m->n_cookies = packet->n_cookies;

        r = genuine_random_bytes(&m->nonce, sizeof(m->nonce), RANDOM_ALLOW_RDRAND);
        if (r < 0)
                return log_error_errno(r, "NTSke: Failed to acquire random data to generate nonce: %m");

        r = genuine_random_bytes(&m->uid, sizeof(m->uid), RANDOM_ALLOW_RDRAND);
        if (r < 0)
                return log_error_errno(r, "NTSke: Failed to acquire random data to generate UID: %m");

        m->c2s_key_size = AEAD_AES_SIV_CMAC_256_KEY_SIZE;
        m->c2s_key_size = AEAD_AES_SIV_CMAC_256_KEY_SIZE;

        r = SSL_export_keying_material(m->ssl, (unsigned char *) &m->c2s_key,
                                       m->c2s_key_size, NTSKE_LABEL, strlen(NTSKE_LABEL),
                                       (unsigned char *) NTSKE_CONTEXT_C2S, 5, 1);
        if (r <= 0) {
                char errbuf[256];

                ERR_error_string_n(r, errbuf, sizeof(errbuf));

                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Failed to extract client to server keys: %s",
                                       errbuf);
        }

        r = SSL_export_keying_material(m->ssl, (unsigned char *) &m->s2c_key,
                                       m->s2c_key_size, NTSKE_LABEL, strlen(NTSKE_LABEL),
                                       (unsigned char *) NTSKE_CONTEXT_S2C, 5, 1);
        if (r <= 0) {
                char errbuf[256];

                ERR_error_string_n(r, errbuf, sizeof(errbuf));

                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Failed to extract server to client keys: %s",
                                       errbuf);
        }

        return 0;
}

int ntske_tls_send_request(Manager *m) {
        _cleanup_(ntske_packet_freep) NTSKEPacket *packet = NULL;
        int error, r;
        ssize_t ss;

        assert(m);

        r = ntske_build_request_packet(&packet);
        if (r < 0)
                return r;

        assert(m->ssl);

        ERR_clear_error();
        ss = r = SSL_write(m->ssl, packet->data, packet->size);
        if (r <= 0) {
                error = SSL_get_error(m->ssl, r);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        ss = -EAGAIN;
                } else if (error == SSL_ERROR_ZERO_RETURN) {
                        ss = 0;
                } else {
                        char errbuf[256];

                        ERR_error_string_n(error, errbuf, sizeof(errbuf));
                        log_debug("Failed to invoke SSL_write: %s", errbuf);
                        ss = -EPIPE;
                }
        }

        return ss;
}

int ntske_tls_receive_response(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_(ntske_packet_freep) NTSKEPacket *packet = NULL;
        Manager *m = userdata;
        ServerName *s;
        int error, r;

        assert(source);
        assert(m);
        assert(m->ssl);

        if (revents & (EPOLLHUP|EPOLLERR)) {
                log_warning("NTSke: Server connection returned error.");
                goto error;
        }

        if (!m->ntske_packet) {
                r = nts_ke_packet_new(NTS_KE_MESSAGE_SIZE_MAX, &packet);
                if (r < 0)
                        goto error;
        }

        ERR_clear_error();
        r = SSL_read(m->ssl, packet->data + packet->read, NTS_KE_MESSAGE_SIZE_MAX - packet->read);
        if (r <= 0) {
                error = SSL_get_error(m->ssl, r);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        return 1;
                } else if (error == SSL_ERROR_ZERO_RETURN) {
                        r = 0;
                } else {
                        char errbuf[256];

                        ERR_error_string_n(error, errbuf, sizeof(errbuf));
                        log_debug("NTSke: Failed to invoke SSL_read: %s", errbuf);
                        goto error;
                }
        }

        packet->size += r;
        packet->payload = true;

        log_debug("Received '%d' bytes from NTSke server", (int) packet->size);

        r = ntske_parse_packet(packet);
        if (r < 0) {
                log_error_errno(r, "Failed to parse NTSke packet: %m");
                goto error;
        }

        r = server_name_new(m, &s, SERVER_SYSTEM, packet->server ? packet->server: m->current_ntske_server_name->string);
        if (r < 0) {
                log_error_errno(r, "Failed to add NTP server '%s' received from NTSke server: %m", packet->server);
                goto error;
        }

        r = ntske_aquire_auth_data(m, packet);
        if (r < 0)
                goto error;

        /* Drop the payload */
        ntske_packet_drop_payload(packet);
        m->ntske_packet = TAKE_PTR(packet);
        m->ntske_done = true;

 error:
        return manager_connect(m);
}

static bool ntske_openssl_read_x509_certificate(SSL *ssl) {
        _cleanup_(X509_freep) X509 *x509 = NULL;
        _cleanup_free_ char *t = NULL;
        X509_NAME *name = NULL;
        int r;

        assert(ssl);

        x509 = SSL_get_peer_certificate(ssl);
        if (!x509)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "NTSke: Failed to acquire X.509 peer ceritficate.");

        name = X509_get_subject_name(x509);
        if (!name)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "NTSke: Failed to acquire X.509 subject name.");

        t = X509_NAME_oneline(name, NULL, 0);
        if (!t)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "NTSke: Failed to format X.509 subject name as string.");

        log_debug("NTSke: Using X.509 certificate issued for '%s'.", t);

        r = SSL_get_verify_result(ssl);
        if (X509_V_OK == r)
                log_debug("NTSke: certificate is valid.");
        else
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "NTSke: certificate is invalid: %d=>%s", r, X509_verify_cert_error_string(r));

        return 0;
}

int ntske_openssl_connect(Manager *manager) {
        _cleanup_(SSL_freep) SSL *s = NULL;
        X509_VERIFY_PARAM *v;
        int error, r;

        assert(manager);

        s = SSL_new(manager->client_ctx);
        if (!s)
                return -ENOMEM;

        SSL_set_fd(s, manager->ntske_server_socket);
        SSL_set_verify(s, SSL_VERIFY_PEER, NULL);

        v = SSL_get0_param(s);
        if (manager->current_ntske_server_name->string) {
                X509_VERIFY_PARAM_set_hostflags(v, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                if (X509_VERIFY_PARAM_set1_host(v, manager->current_ntske_server_name->string, 0) == 0)
                        return -ECONNREFUSED;
        } else {
                const unsigned char *ip;
                int family = manager->current_ntske_server_address->sockaddr.sa.sa_family;

                switch(family) {
                case AF_INET:
                        ip = (unsigned char *) &manager->current_ntske_server_address->sockaddr.in.sin_addr.s_addr;
                        break;
                case AF_INET6:
                        ip = (unsigned char *) &manager->current_ntske_server_address->sockaddr.in6.sin6_addr;
                default:
                        break;
                }

                if (X509_VERIFY_PARAM_set1_ip(v, ip, FAMILY_ADDRESS_SIZE(family)) == 0)
                        return -ECONNREFUSED;
        }

        r = SSL_connect(s);
        if (r < 0) {
                error = SSL_get_error(s, manager->handshake);
                if (!IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        char errbuf[256];

                        ERR_error_string_n(error, errbuf, sizeof(errbuf));
                        return log_debug_errno(SYNTHETIC_ERRNO(ECONNREFUSED),
                                               "NTSke: Failed to invoke SSL_connect: %s", errbuf);
                }
        }

        ERR_clear_error();
        manager->handshake = SSL_do_handshake(s);
        if (manager->handshake <= 0) {
                error = SSL_get_error(s, manager->handshake);
                if (!IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        char errbuf[256];

                        ERR_error_string_n(error, errbuf, sizeof(errbuf));
                        return log_debug_errno(SYNTHETIC_ERRNO(ECONNREFUSED),
                                               "NTSke: Failed to invoke SSL_do_handshake: %s", errbuf);
                }
        }

        log_debug("NTSc: Using %s, %s (%d)", SSL_get_version(s), SSL_get_cipher_name(s), SSL_get_cipher_bits(s, NULL));

        r = ntske_openssl_read_x509_certificate(s);
        if (r < 0)
                return r;

        manager->ssl = TAKE_PTR(s);

        return 0;
}

int ntske_tls_manager_init(Manager *manager) {
        unsigned char alpn[] = { 7, 'n', 't', 's', 'k', 'e', '/', '1' };
        int r;

        assert(manager);

        ERR_load_crypto_strings();
        SSL_load_error_strings();

        manager->client_ctx = SSL_CTX_new(TLS_client_method());
        if (!manager->client_ctx)
                return -ENOMEM;

        r = SSL_CTX_set_min_proto_version(manager->client_ctx, TLS1_2_VERSION);
        if (r == 0)
                return -EIO;

        r = SSL_CTX_set_default_verify_paths(manager->client_ctx);
        if (r == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EIO),
                                         "NTSke: Failed to load system trust store: %s",
                                         ERR_error_string(ERR_get_error(), NULL));

        SSL_CTX_set_alpn_protos(manager->client_ctx, alpn, sizeof(alpn));
        SSL_CTX_set_session_cache_mode(manager->client_ctx, SSL_SESS_CACHE_OFF);

        return 0;
}

void ntske_tls_manager_free(Manager *manager) {
        if (!manager)
                return;

        if (manager->ssl) {
                SSL_free(manager->ssl);
                manager->ssl = NULL;
        }

        if (manager->client_ctx) {
                SSL_CTX_free(manager->client_ctx);
                manager->client_ctx = NULL;
        }
}
