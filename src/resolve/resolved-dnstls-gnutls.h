/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if !ENABLE_DNS_OVER_TLS || !DNS_OVER_TLS_USE_GNUTLS
#error This source file requires DNS-over-TLS to be enabled and GnuTLS to be available.
#endif

#include <gnutls/gnutls.h>
#include <stdbool.h>

struct DnsTlsManagerData {
        gnutls_certificate_credentials_t cert_cred;
};

struct DnsTlsServerData {
        gnutls_datum_t session_data;
};

struct DnsTlsStreamData {
        gnutls_session_t session;
        int handshake;
        bool shutdown;
};
