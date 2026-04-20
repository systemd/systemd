/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_OPENSSL

#  include <openssl/ssl.h>              /* IWYU pragma: export */

#  include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(SSL_CTX_ctrl);
extern DLSYM_PROTOTYPE(SSL_CTX_free);
extern DLSYM_PROTOTYPE(SSL_CTX_new);
extern DLSYM_PROTOTYPE(SSL_CTX_set_default_verify_paths);
extern DLSYM_PROTOTYPE(SSL_CTX_set_options);
extern DLSYM_PROTOTYPE(SSL_SESSION_free);
extern DLSYM_PROTOTYPE(SSL_ctrl);
extern DLSYM_PROTOTYPE(SSL_do_handshake);
extern DLSYM_PROTOTYPE(SSL_free);
extern DLSYM_PROTOTYPE(SSL_get0_param);
extern DLSYM_PROTOTYPE(SSL_get1_session);
extern DLSYM_PROTOTYPE(SSL_get_error);
extern DLSYM_PROTOTYPE(SSL_get_wbio);
extern DLSYM_PROTOTYPE(SSL_new);
extern DLSYM_PROTOTYPE(SSL_read);
extern DLSYM_PROTOTYPE(SSL_set_bio);
extern DLSYM_PROTOTYPE(SSL_set_connect_state);
extern DLSYM_PROTOTYPE(SSL_set_session);
extern DLSYM_PROTOTYPE(SSL_set_verify);
extern DLSYM_PROTOTYPE(SSL_shutdown);
extern DLSYM_PROTOTYPE(SSL_write);
extern DLSYM_PROTOTYPE(TLS_client_method);

int dlopen_libssl(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(SSL*, sym_SSL_free, SSL_freep, NULL);

#else

static inline int dlopen_libssl(void) {
        return -EOPNOTSUPP;
}

#endif
