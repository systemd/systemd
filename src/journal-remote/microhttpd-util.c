/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2012 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "microhttpd-util.h"
#include "log.h"
#include "macro.h"
#include "util.h"
#include "strv.h"

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif

void microhttpd_logger(void *arg, const char *fmt, va_list ap) {
        char *f;

        f = strjoina("microhttpd: ", fmt);

        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(LOG_INFO, 0, NULL, 0, NULL, f, ap);
        REENABLE_WARNING;
}


static int mhd_respond_internal(struct MHD_Connection *connection,
                                enum MHD_RequestTerminationCode code,
                                char *buffer,
                                size_t size,
                                enum MHD_ResponseMemoryMode mode) {
        struct MHD_Response *response;
        int r;

        assert(connection);

        response = MHD_create_response_from_buffer(size, buffer, mode);
        if (!response)
                return MHD_NO;

        log_debug("Queing response %u: %s", code, buffer);
        MHD_add_response_header(response, "Content-Type", "text/plain");
        r = MHD_queue_response(connection, code, response);
        MHD_destroy_response(response);

        return r;
}

int mhd_respond(struct MHD_Connection *connection,
                enum MHD_RequestTerminationCode code,
                const char *message) {

        return mhd_respond_internal(connection, code,
                                    (char*) message, strlen(message),
                                    MHD_RESPMEM_PERSISTENT);
}

int mhd_respond_oom(struct MHD_Connection *connection) {
        return mhd_respond(connection, MHD_HTTP_SERVICE_UNAVAILABLE,  "Out of memory.\n");
}

int mhd_respondf(struct MHD_Connection *connection,
                 enum MHD_RequestTerminationCode code,
                 const char *format, ...) {

        char *m;
        int r;
        va_list ap;

        assert(connection);
        assert(format);

        va_start(ap, format);
        r = vasprintf(&m, format, ap);
        va_end(ap);

        if (r < 0)
                return respond_oom(connection);

        return mhd_respond_internal(connection, code, m, r, MHD_RESPMEM_MUST_FREE);
}

#ifdef HAVE_GNUTLS

static struct {
        const char *const names[4];
        int level;
        bool enabled;
} gnutls_log_map[] = {
        { {"0"},                  LOG_DEBUG },
        { {"1", "audit"},         LOG_WARNING, true}, /* gnutls session audit */
        { {"2", "assert"},        LOG_DEBUG },        /* gnutls assert log */
        { {"3", "hsk", "ext"},    LOG_DEBUG },        /* gnutls handshake log */
        { {"4", "rec"},           LOG_DEBUG },        /* gnutls record log */
        { {"5", "dtls"},          LOG_DEBUG },        /* gnutls DTLS log */
        { {"6", "buf"},           LOG_DEBUG },
        { {"7", "write", "read"}, LOG_DEBUG },
        { {"8"},                  LOG_DEBUG },
        { {"9", "enc", "int"},    LOG_DEBUG },
};

static void log_func_gnutls(int level, const char *message) {
        assert_se(message);

        if (0 <= level && level < (int) ELEMENTSOF(gnutls_log_map)) {
                if (gnutls_log_map[level].enabled)
                        log_internal(gnutls_log_map[level].level, 0, NULL, 0, NULL, "gnutls %d/%s: %s", level, gnutls_log_map[level].names[1], message);
        } else {
                log_debug("Received GNUTLS message with unknown level %d.", level);
                log_internal(LOG_DEBUG, 0, NULL, 0, NULL, "gnutls: %s", message);
        }
}

static void log_reset_gnutls_level(void) {
        int i;

        for (i = ELEMENTSOF(gnutls_log_map) - 1; i >= 0; i--)
                if (gnutls_log_map[i].enabled) {
                        log_debug("Setting gnutls log level to %d", i);
                        gnutls_global_set_log_level(i);
                        break;
                }
}

static int log_enable_gnutls_category(const char *cat) {
        unsigned i;

        if (streq(cat, "all")) {
                for (i = 0; i < ELEMENTSOF(gnutls_log_map); i++)
                        gnutls_log_map[i].enabled = true;
                log_reset_gnutls_level();
                return 0;
        } else
                for (i = 0; i < ELEMENTSOF(gnutls_log_map); i++)
                        if (strv_contains((char**)gnutls_log_map[i].names, cat)) {
                                gnutls_log_map[i].enabled = true;
                                log_reset_gnutls_level();
                                return 0;
                        }
        log_error("No such log category: %s", cat);
        return -EINVAL;
}

int setup_gnutls_logger(char **categories) {
        char **cat;
        int r;

        gnutls_global_set_log_function(log_func_gnutls);

        if (categories) {
                STRV_FOREACH(cat, categories) {
                        r = log_enable_gnutls_category(*cat);
                        if (r < 0)
                                return r;
                }
        } else
                log_reset_gnutls_level();

        return 0;
}

static int verify_cert_authorized(gnutls_session_t session) {
        unsigned status;
        gnutls_certificate_type_t type;
        gnutls_datum_t out;
        int r;

        r = gnutls_certificate_verify_peers2(session, &status);
        if (r < 0)
                return log_error_errno(r, "gnutls_certificate_verify_peers2 failed: %m");

        type = gnutls_certificate_type_get(session);
        r = gnutls_certificate_verification_status_print(status, type, &out, 0);
        if (r < 0)
                return log_error_errno(r, "gnutls_certificate_verification_status_print failed: %m");

        log_debug("Certificate status: %s", out.data);
        gnutls_free(out.data);

        return status == 0 ? 0 : -EPERM;
}

static int get_client_cert(gnutls_session_t session, gnutls_x509_crt_t *client_cert) {
        const gnutls_datum_t *pcert;
        unsigned listsize;
        gnutls_x509_crt_t cert;
        int r;

        assert(session);
        assert(client_cert);

        pcert = gnutls_certificate_get_peers(session, &listsize);
        if (!pcert || !listsize) {
                log_error("Failed to retrieve certificate chain");
                return -EINVAL;
        }

        r = gnutls_x509_crt_init(&cert);
        if (r < 0) {
                log_error("Failed to initialize client certificate");
                return r;
        }

        /* Note that by passing values between 0 and listsize here, you
           can get access to the CA's certs */
        r = gnutls_x509_crt_import(cert, &pcert[0], GNUTLS_X509_FMT_DER);
        if (r < 0) {
                log_error("Failed to import client certificate");
                gnutls_x509_crt_deinit(cert);
                return r;
        }

        *client_cert = cert;
        return 0;
}

static int get_auth_dn(gnutls_x509_crt_t client_cert, char **buf) {
        size_t len = 0;
        int r;

        assert(buf);
        assert(*buf == NULL);

        r = gnutls_x509_crt_get_dn(client_cert, NULL, &len);
        if (r != GNUTLS_E_SHORT_MEMORY_BUFFER) {
                log_error("gnutls_x509_crt_get_dn failed");
                return r;
        }

        *buf = malloc(len);
        if (!*buf)
                return log_oom();

        gnutls_x509_crt_get_dn(client_cert, *buf, &len);
        return 0;
}

static inline void gnutls_x509_crt_deinitp(gnutls_x509_crt_t *p) {
        gnutls_x509_crt_deinit(*p);
}

int check_permissions(struct MHD_Connection *connection, int *code, char **hostname) {
        const union MHD_ConnectionInfo *ci;
        gnutls_session_t session;
        _cleanup_(gnutls_x509_crt_deinitp) gnutls_x509_crt_t client_cert = NULL;
        _cleanup_free_ char *buf = NULL;
        int r;

        assert(connection);
        assert(code);

        *code = 0;

        ci = MHD_get_connection_info(connection,
                                     MHD_CONNECTION_INFO_GNUTLS_SESSION);
        if (!ci) {
                log_error("MHD_get_connection_info failed: session is unencrypted");
                *code = mhd_respond(connection, MHD_HTTP_FORBIDDEN,
                                    "Encrypted connection is required");
                return -EPERM;
        }
        session = ci->tls_session;
        assert(session);

        r = get_client_cert(session, &client_cert);
        if (r < 0) {
                *code = mhd_respond(connection, MHD_HTTP_UNAUTHORIZED,
                                    "Authorization through certificate is required");
                return -EPERM;
        }

        r = get_auth_dn(client_cert, &buf);
        if (r < 0) {
                *code = mhd_respond(connection, MHD_HTTP_UNAUTHORIZED,
                                    "Failed to determine distinguished name from certificate");
                return -EPERM;
        }

        log_debug("Connection from %s", buf);

        if (hostname) {
                *hostname = buf;
                buf = NULL;
        }

        r = verify_cert_authorized(session);
        if (r < 0) {
                log_warning("Client is not authorized");
                *code = mhd_respond(connection, MHD_HTTP_UNAUTHORIZED,
                                    "Client certificate not signed by recognized authority");
        }
        return r;
}

#else
int check_permissions(struct MHD_Connection *connection, int *code, char **hostname) {
        return -EPERM;
}

int setup_gnutls_logger(char **categories) {
        if (categories)
                log_notice("Ignoring specified gnutls logging categories — gnutls not available.");
        return 0;
}
#endif
