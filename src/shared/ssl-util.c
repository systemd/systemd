/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dlopen.h"

#include "log.h"                /* IWYU pragma: keep */
#include "ssl-util.h"

#if HAVE_OPENSSL

static void *libssl_dl = NULL;

DLSYM_PROTOTYPE(SSL_ctrl) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_ctrl) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_free) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_new) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_set_default_verify_paths) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_set_options) = NULL;
DLSYM_PROTOTYPE(SSL_do_handshake) = NULL;
DLSYM_PROTOTYPE(SSL_free) = NULL;
DLSYM_PROTOTYPE(SSL_get_error) = NULL;
DLSYM_PROTOTYPE(SSL_get_wbio) = NULL;
DLSYM_PROTOTYPE(SSL_get0_param) = NULL;
DLSYM_PROTOTYPE(SSL_get1_session) = NULL;
DLSYM_PROTOTYPE(SSL_new) = NULL;
DLSYM_PROTOTYPE(SSL_read) = NULL;
DLSYM_PROTOTYPE(SSL_SESSION_free) = NULL;
DLSYM_PROTOTYPE(SSL_set_bio) = NULL;
DLSYM_PROTOTYPE(SSL_set_connect_state) = NULL;
DLSYM_PROTOTYPE(SSL_set_session) = NULL;
DLSYM_PROTOTYPE(SSL_set_verify) = NULL;
DLSYM_PROTOTYPE(SSL_shutdown) = NULL;
DLSYM_PROTOTYPE(SSL_write) = NULL;
DLSYM_PROTOTYPE(TLS_client_method) = NULL;

#endif

int dlopen_libssl(int log_level) {
#if HAVE_OPENSSL
        SD_ELF_NOTE_DLOPEN(
                        "libssl",
                        "Support for TLS",
                        SD_ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libssl.so.3");

        return dlopen_many_sym_or_warn(
                        &libssl_dl,
                        "libssl.so.3",
                        log_level,
                        DLSYM_ARG(SSL_ctrl),
                        DLSYM_ARG(SSL_CTX_ctrl),
                        DLSYM_ARG(SSL_CTX_free),
                        DLSYM_ARG(SSL_CTX_new),
                        DLSYM_ARG(SSL_CTX_set_default_verify_paths),
                        DLSYM_ARG(SSL_CTX_set_options),
                        DLSYM_ARG(SSL_do_handshake),
                        DLSYM_ARG(SSL_free),
                        DLSYM_ARG(SSL_get_error),
                        DLSYM_ARG(SSL_get_wbio),
                        DLSYM_ARG(SSL_get0_param),
                        DLSYM_ARG(SSL_get1_session),
                        DLSYM_ARG(SSL_new),
                        DLSYM_ARG(SSL_read),
                        DLSYM_ARG(SSL_SESSION_free),
                        DLSYM_ARG(SSL_set_bio),
                        DLSYM_ARG(SSL_set_connect_state),
                        DLSYM_ARG(SSL_set_session),
                        DLSYM_ARG(SSL_set_verify),
                        DLSYM_ARG(SSL_shutdown),
                        DLSYM_ARG(SSL_write),
                        DLSYM_ARG(TLS_client_method));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "libssl support is not compiled in.");
#endif
}
