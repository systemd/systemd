/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-dlopen.h"

#include "alloc-util.h"
#include "gnutls-util.h"
#include "log.h"
#include "microhttpd-util.h"
#include "string-util.h"
#include "strv.h"

#if HAVE_MICROHTTPD
static void *microhttpd_dl = NULL;

DLSYM_PROTOTYPE(MHD_add_response_header) = NULL;
DLSYM_PROTOTYPE(MHD_create_response_from_buffer) = NULL;
DLSYM_PROTOTYPE(MHD_create_response_from_callback) = NULL;
#if MHD_VERSION < 0x00094203
DLSYM_PROTOTYPE(MHD_create_response_from_fd_at_offset) = NULL;
#else
DLSYM_PROTOTYPE(MHD_create_response_from_fd_at_offset64) = NULL;
#endif
DLSYM_PROTOTYPE(MHD_destroy_response) = NULL;
DLSYM_PROTOTYPE(MHD_get_connection_info) = NULL;
DLSYM_PROTOTYPE(MHD_get_connection_values) = NULL;
DLSYM_PROTOTYPE(MHD_get_daemon_info) = NULL;
DLSYM_PROTOTYPE(MHD_get_timeout) = NULL;
DLSYM_PROTOTYPE(MHD_lookup_connection_value) = NULL;
DLSYM_PROTOTYPE(MHD_queue_response) = NULL;
DLSYM_PROTOTYPE(MHD_run) = NULL;
DLSYM_PROTOTYPE(MHD_start_daemon) = NULL;
DLSYM_PROTOTYPE(MHD_stop_daemon) = NULL;
#endif

int dlopen_microhttpd(int log_level) {
#if HAVE_MICROHTTPD
        SD_ELF_NOTE_DLOPEN(
                        "microhttpd",
                        "Support for embedded HTTP server via libmicrohttpd",
                        SD_ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libmicrohttpd.so.12");

        return dlopen_many_sym_or_warn(
                        &microhttpd_dl,
                        "libmicrohttpd.so.12",
                        log_level,
                        DLSYM_ARG(MHD_add_response_header),
                        DLSYM_ARG(MHD_create_response_from_buffer),
                        DLSYM_ARG(MHD_create_response_from_callback),
#if MHD_VERSION < 0x00094203
                        DLSYM_ARG(MHD_create_response_from_fd_at_offset),
#else
                        DLSYM_ARG(MHD_create_response_from_fd_at_offset64),
#endif
                        DLSYM_ARG(MHD_destroy_response),
                        DLSYM_ARG(MHD_get_connection_info),
                        DLSYM_ARG(MHD_get_connection_values),
                        DLSYM_ARG(MHD_get_daemon_info),
                        DLSYM_ARG(MHD_get_timeout),
                        DLSYM_ARG(MHD_lookup_connection_value),
                        DLSYM_ARG(MHD_queue_response),
                        DLSYM_ARG(MHD_run),
                        DLSYM_ARG(MHD_start_daemon),
                        DLSYM_ARG(MHD_stop_daemon));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "libmicrohttpd support is not compiled in.");
#endif
}

#if HAVE_MICROHTTPD

void microhttpd_logger(void *arg, const char *fmt, va_list ap) {
        char *f;

        f = strjoina("microhttpd: ", fmt);

        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(LOG_INFO, 0, NULL, 0, NULL, f, ap);
        REENABLE_WARNING;
}

int mhd_respond_internal(
                struct MHD_Connection *connection,
                enum MHD_RequestTerminationCode code,
                const char *encoding,
                const char *buffer,
                size_t size,
                enum MHD_ResponseMemoryMode mode) {

        assert(connection);

        _cleanup_(MHD_destroy_responsep) struct MHD_Response *response
                = sym_MHD_create_response_from_buffer(size, (char*) buffer, mode);
        if (!response)
                return MHD_NO;

        log_debug("Queueing response %u: %s", code, buffer);
        if (encoding)
                if (sym_MHD_add_response_header(response, "Accept-Encoding", encoding) == MHD_NO)
                        return MHD_NO;

        if (sym_MHD_add_response_header(response, "Content-Type", "text/plain") == MHD_NO)
                return MHD_NO;
        return sym_MHD_queue_response(connection, code, response);
}

int mhd_respond_oom(struct MHD_Connection *connection) {
        return mhd_respond(connection, MHD_HTTP_SERVICE_UNAVAILABLE, "Out of memory.");
}

int mhd_respondf_internal(
                struct MHD_Connection *connection,
                int error,
                enum MHD_RequestTerminationCode code,
                const char *encoding,
                const char *format, ...) {

        char *m;
        int r;
        va_list ap;

        assert(connection);
        assert(format);

        errno = ERRNO_VALUE(error);
        va_start(ap, format);
        r = vasprintf(&m, format, ap);
        va_end(ap);

        if (r < 0)
                return respond_oom(connection);

        return mhd_respond_internal(connection, code, encoding, m, r, MHD_RESPMEM_MUST_FREE);
}

#if HAVE_GNUTLS

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
                        sym_gnutls_global_set_log_level(i);
                        break;
                }
}

static int log_enable_gnutls_category(const char *cat) {
        if (streq(cat, "all")) {
                FOREACH_ELEMENT(entry, gnutls_log_map)
                        entry->enabled = true;
                log_reset_gnutls_level();
                return 0;
        } else
                FOREACH_ELEMENT(entry, gnutls_log_map)
                        if (strv_contains((char**)entry->names, cat)) {
                                entry->enabled = true;
                                log_reset_gnutls_level();
                                return 0;
                        }
        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No such log category: %s", cat);
}

int setup_gnutls_logger(char **categories) {
        int r;

        r = dlopen_gnutls(LOG_DEBUG);
        if (r < 0) {
                if (categories)
                        log_notice("Ignoring specified gnutls logging categories -- gnutls not available.");
                else
                        log_debug("GnuTLS not available, skipping logger setup.");
                return 0;
        }

        sym_gnutls_global_set_log_function(log_func_gnutls);

        if (categories)
                STRV_FOREACH(cat, categories) {
                        r = log_enable_gnutls_category(*cat);
                        if (r < 0)
                                return r;
                }
        else
                log_reset_gnutls_level();

        return 0;
}

static int verify_cert_authorized(gnutls_session_t session) {
        unsigned status;
        gnutls_certificate_type_t type;
        gnutls_datum_t out;
        int r;

        r = sym_gnutls_certificate_verify_peers2(session, &status);
        if (r < 0)
                return log_error_errno(r, "gnutls_certificate_verify_peers2 failed: %m");

        type = sym_gnutls_certificate_type_get(session);
        r = sym_gnutls_certificate_verification_status_print(status, type, &out, 0);
        if (r < 0)
                return log_error_errno(r, "gnutls_certificate_verification_status_print failed: %m");

        log_debug("Certificate status: %s", out.data);
        /* gnutls_free is declared as a function pointer variable (not a function), so sym_gnutls_free
         * ends up as a pointer-to-function-pointer and must be explicitly dereferenced to be called. */
        (*sym_gnutls_free)(out.data);

        return status == 0 ? 0 : -EPERM;
}

static int get_client_cert(gnutls_session_t session, gnutls_x509_crt_t *client_cert) {
        const gnutls_datum_t *pcert;
        unsigned listsize;
        gnutls_x509_crt_t cert;
        int r;

        assert(session);
        assert(client_cert);

        pcert = sym_gnutls_certificate_get_peers(session, &listsize);
        if (!pcert || !listsize)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to retrieve certificate chain");

        r = sym_gnutls_x509_crt_init(&cert);
        if (r < 0) {
                log_error("Failed to initialize client certificate");
                return r;
        }

        /* Note that by passing values between 0 and listsize here, you
           can get access to the CA's certs */
        r = sym_gnutls_x509_crt_import(cert, &pcert[0], GNUTLS_X509_FMT_DER);
        if (r < 0) {
                log_error("Failed to import client certificate");
                sym_gnutls_x509_crt_deinit(cert);
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

        r = sym_gnutls_x509_crt_get_dn(client_cert, NULL, &len);
        if (r != GNUTLS_E_SHORT_MEMORY_BUFFER) {
                log_error("gnutls_x509_crt_get_dn failed");
                return r;
        }

        *buf = malloc(len);
        if (!*buf)
                return log_oom();

        sym_gnutls_x509_crt_get_dn(client_cert, *buf, &len);
        return 0;
}

static void gnutls_x509_crt_deinitp(gnutls_x509_crt_t *p) {
        assert(p);

        if (*p)
                sym_gnutls_x509_crt_deinit(*p);
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

        r = dlopen_gnutls(LOG_ERR);
        if (r < 0)
                return r;

        ci = sym_MHD_get_connection_info(connection,
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

        if (hostname)
                *hostname = TAKE_PTR(buf);

        r = verify_cert_authorized(session);
        if (r < 0) {
                log_warning("Client is not authorized");
                *code = mhd_respond(connection, MHD_HTTP_UNAUTHORIZED,
                                    "Client certificate not signed by recognized authority");
        }
        return r;
}

#else
_noreturn_ int check_permissions(struct MHD_Connection *connection, int *code, char **hostname) {
        assert_not_reached();
}

int setup_gnutls_logger(char **categories) {
        if (categories)
                log_notice("Ignoring specified gnutls logging categories — gnutls not available.");
        return 0;
}
#endif

#endif
