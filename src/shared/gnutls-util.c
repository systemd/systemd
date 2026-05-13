/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dlopen.h"

#include "gnutls-util.h"
#include "log.h"                /* IWYU pragma: keep */

#if HAVE_GNUTLS
static void *gnutls_dl = NULL;

DLSYM_PROTOTYPE(gnutls_certificate_get_peers) = NULL;
DLSYM_PROTOTYPE(gnutls_certificate_type_get) = NULL;
DLSYM_PROTOTYPE(gnutls_certificate_verification_status_print) = NULL;
DLSYM_PROTOTYPE(gnutls_certificate_verify_peers2) = NULL;
DLSYM_PROTOTYPE(gnutls_free) = NULL;
DLSYM_PROTOTYPE(gnutls_global_set_log_function) = NULL;
DLSYM_PROTOTYPE(gnutls_global_set_log_level) = NULL;
DLSYM_PROTOTYPE(gnutls_x509_crt_deinit) = NULL;
DLSYM_PROTOTYPE(gnutls_x509_crt_get_dn) = NULL;
DLSYM_PROTOTYPE(gnutls_x509_crt_import) = NULL;
DLSYM_PROTOTYPE(gnutls_x509_crt_init) = NULL;
#endif

int dlopen_gnutls(int log_level) {
#if HAVE_GNUTLS
        SD_ELF_NOTE_DLOPEN(
                        "gnutls",
                        "Support for TLS via GnuTLS",
                        SD_ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libgnutls.so.30");

        return dlopen_many_sym_or_warn(
                        &gnutls_dl,
                        "libgnutls.so.30",
                        log_level,
                        DLSYM_ARG(gnutls_certificate_get_peers),
                        DLSYM_ARG(gnutls_certificate_type_get),
                        DLSYM_ARG(gnutls_certificate_verification_status_print),
                        DLSYM_ARG(gnutls_certificate_verify_peers2),
                        DLSYM_ARG(gnutls_free),
                        DLSYM_ARG(gnutls_global_set_log_function),
                        DLSYM_ARG(gnutls_global_set_log_level),
                        DLSYM_ARG(gnutls_x509_crt_deinit),
                        DLSYM_ARG(gnutls_x509_crt_get_dn),
                        DLSYM_ARG(gnutls_x509_crt_import),
                        DLSYM_ARG(gnutls_x509_crt_init));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "gnutls support is not compiled in.");
#endif
}
