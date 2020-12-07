/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "alloc-util.h"
#include "log.h"
#include "random-util.h"
#include "timesyncd-ntske-client.h"
#include "timesyncd-ntske-protocol.h"

#ifndef GNUTLS_CIPHER_AES_128_SIV
#define GNUTLS_CIPHER_AES_128_SIV  37
#endif

#if GNUTLS_FOR_NTS
DEFINE_TRIVIAL_CLEANUP_FUNC(gnutls_session_t, gnutls_deinit);
#endif

int aead_ciphers_to_gnu_tls_cipher_algorithm(int c) {
        switch(c) {
        case AEAD_AES_SIV_CMAC_256:
                return GNUTLS_CIPHER_AES_128_SIV;
                break;
        default:
                break;
        }

        return -ENOTSUP;
}

static int ntske_aquire_auth_data(Manager *m, NTSKEPacket *packet) {
#if GNUTLS_FOR_NTS
        gnutls_cipher_algorithm_t algorithm;
        size_t key_size;
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
                return log_error_errno(r, "NTS: Failed to acquire random data to generate nonce: %m");

        r = genuine_random_bytes(&m->uid, sizeof(m->uid), RANDOM_ALLOW_RDRAND);
        if (r < 0)
                return log_error_errno(r, "NTS: Failed to acquire random data to generate UID: %m");


        algorithm = aead_ciphers_to_gnu_tls_cipher_algorithm(m->aead_algorithm);
        key_size = gnutls_cipher_get_key_size(algorithm);

        /* Extract the server and client keys */
        r = gnutls_prf_rfc5705(m->tls_session,
                               sizeof(NTSKE_LABEL) - 1, NTSKE_LABEL,
                               sizeof(NTSKE_CONTEXT_C2S) - 1, NTSKE_CONTEXT_C2S,
                               key_size, (char *) m->c2s_key);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to extract client to server keys: %s",
                                       gnutls_strerror(r));

        r = gnutls_prf_rfc5705(m->tls_session,
                               sizeof(NTSKE_LABEL) - 1, NTSKE_LABEL,
                               sizeof(NTSKE_CONTEXT_S2C) - 1, NTSKE_CONTEXT_S2C,
                               key_size, (char *) m->s2c_key);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to extract server to client keys: %s",
                                       gnutls_strerror(r));


        m->c2s_key_size = m->s2c_key_size = key_size;
#endif
        return 0;
}

int ntske_tls_send_request(Manager *m) {
        _cleanup_(ntske_packet_freep) NTSKEPacket *packet = NULL;
        int r;

        assert(m);

        r = ntske_build_request_packet(&packet);
        if (r < 0)
                return r;
#if GNUTLS_FOR_NTS

        assert(m->tls_session);

        r = gnutls_record_send(m->tls_session, packet->data, packet->size);
        if (r < 0) {
                if (gnutls_error_is_fatal(r))
                        return r;
        }
#endif

        return 0;
}

int ntske_tls_receive_response(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_(ntske_packet_freep) NTSKEPacket *packet = NULL;
        Manager *m = userdata;
        ServerName *s;
        int r;

        assert(source);
        assert(m);

        if (revents & (EPOLLHUP|EPOLLERR)) {
                log_warning("Server connection returned error.");
                goto error;
        }

        if (!m->ntske_packet) {
                r = nts_ke_packet_new(NTS_KE_MESSAGE_SIZE_MAX, &packet);
                if (r < 0)
                        goto error;
        }

#if GNUTLS_FOR_NTS

        r = gnutls_record_recv(m->tls_session, packet->data + packet->read, NTS_KE_MESSAGE_SIZE_MAX - packet->read);
        if (r < 0) {
                if (IN_SET(r, GNUTLS_E_INTERRUPTED, GNUTLS_E_AGAIN))
                        return 1;

                if (gnutls_error_is_fatal(r)) {
                        log_debug_errno(r,
                                        "Failed to invoke gnutls_record_recv: %s",
                                        gnutls_strerror(r));
                        goto error;
                }

                r = 0;
        }

#endif
        packet->size += r;
        packet->payload = true;

        log_debug("Received '%d' bytes from NTSKE server", (int) packet->size);

        r = ntske_parse_packet(packet);
        if (r < 0) {
                log_error_errno(r, "Failed to parse NTSKE packet: %m");
                goto error;
        }

        r = server_name_new(m, &s, SERVER_SYSTEM, packet->server ? packet->server: m->current_ntske_server_name->string);
        if (r < 0) {
                log_error_errno(r, "Failed to add NTP server '%s' received from NTSKE server: %m", packet->server);
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

int ntske_tls_connect(Manager *m) {
#if GNUTLS_FOR_NTS
        _cleanup_(gnutls_deinitp) gnutls_session_t tls_session = NULL;
        gnutls_datum_t alpn = {
                .data = (uint8_t *) "ntske/1",
                .size = sizeof("ntske/1") - 1,
        };
        int r;

        assert(m);

        r = ntske_tls_manager_init(m);
        if (r < 0)
                return r;

        r = gnutls_init(&tls_session, GNUTLS_CLIENT | GNUTLS_NO_SIGNAL | GNUTLS_NONBLOCK);
        if (r < 0)
                return r;

        gnutls_transport_set_int(tls_session, m->ntske_server_socket);

        if (m->current_ntske_server_name->string) {
                r = gnutls_server_name_set(tls_session, GNUTLS_NAME_DNS, m->current_ntske_server_name->string, strlen(m->current_ntske_server_name->string));
                if (r < 0)
                        return r;
        }

        r = gnutls_priority_init2(&m->priority_cache,
                                  "-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2:-VERS-DTLS-ALL",
                                  NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND);

        r = gnutls_priority_set(tls_session, m->priority_cache);
        if (r < 0)
                return r;

        r = gnutls_credentials_set(tls_session, GNUTLS_CRD_CERTIFICATE, m->cert_cred);
        if (r < 0)
                return r;

        r = gnutls_alpn_set_protocols(tls_session, &alpn, 1, 0);
        if (r < 0)
                return r;

        gnutls_handshake_set_timeout(tls_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        m->handshake = gnutls_handshake(tls_session);
        if (m->handshake < 0 && gnutls_error_is_fatal(m->handshake))
                return -ECONNREFUSED;

        m->tls_session = TAKE_PTR(tls_session);
#endif
        return 0;
}

void ntske_tls_bye(Manager *m) {
#if GNUTLS_FOR_NTS
        int r;

        assert(m);

        if (!m->tls_session)
                return;

        r = gnutls_bye(m->tls_session, GNUTLS_SHUT_RDWR);
        if (r < 0) {
                if (gnutls_error_is_fatal(r))
                        log_error_errno(r, "GnuTLS Shutdown failed woth '%s': %m", gnutls_strerror(r));
        }

        gnutls_deinit(m->tls_session);
        m->tls_session = NULL;

#endif
}

int ntske_tls_manager_init(Manager *manager) {
#if GNUTLS_FOR_NTS
        int r;

        assert(manager);

        ntske_tls_manager_free(manager);

        r = gnutls_certificate_allocate_credentials(&manager->cert_cred);
        if (r < 0)
                return -ENOMEM;

        r = gnutls_certificate_set_x509_system_trust(manager->cert_cred);
        if (r < 0)
                log_warning("Failed to load system trust store: %s", gnutls_strerror(r));

#endif
        return 0;
}

void ntske_tls_manager_free(Manager *manager) {
        assert(manager);

#if GNUTLS_FOR_NTS

        if (manager->cert_cred) {
                gnutls_certificate_free_credentials(manager->cert_cred);
                manager->cert_cred = NULL;
        }

#endif
}
