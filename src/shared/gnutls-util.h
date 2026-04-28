/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int dlopen_gnutls(int log_level);

#if HAVE_GNUTLS
#  include <gnutls/gnutls.h>    /* IWYU pragma: export */
#  include <gnutls/x509.h>      /* IWYU pragma: export */

/* gnutls.h installs a function-like macro that wraps gnutls_free() and NULLs the passed pointer. We use
 * dlsym to resolve the underlying function pointer variable, so undef the macro here to keep the variable
 * name visible for DLSYM_PROTOTYPE/DLSYM_ARG. */
#  ifdef gnutls_free
#    undef gnutls_free
#  endif

#  include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(gnutls_certificate_get_peers);
extern DLSYM_PROTOTYPE(gnutls_certificate_type_get);
extern DLSYM_PROTOTYPE(gnutls_certificate_verification_status_print);
extern DLSYM_PROTOTYPE(gnutls_certificate_verify_peers2);
extern DLSYM_PROTOTYPE(gnutls_free);
extern DLSYM_PROTOTYPE(gnutls_global_set_log_function);
extern DLSYM_PROTOTYPE(gnutls_global_set_log_level);
extern DLSYM_PROTOTYPE(gnutls_x509_crt_deinit);
extern DLSYM_PROTOTYPE(gnutls_x509_crt_get_dn);
extern DLSYM_PROTOTYPE(gnutls_x509_crt_import);
extern DLSYM_PROTOTYPE(gnutls_x509_crt_init);
#endif
