/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int dlopen_libssl(int log_level);

#if HAVE_OPENSSL

#  include <openssl/ssl.h>              /* IWYU pragma: export */

#  include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(SSL_ctrl);
extern DLSYM_PROTOTYPE(SSL_CTX_ctrl);
extern DLSYM_PROTOTYPE(SSL_CTX_free);
extern DLSYM_PROTOTYPE(SSL_CTX_new);
extern DLSYM_PROTOTYPE(SSL_CTX_set_default_verify_paths);
extern DLSYM_PROTOTYPE(SSL_CTX_set_options);
extern DLSYM_PROTOTYPE(SSL_do_handshake);
extern DLSYM_PROTOTYPE(SSL_free);
extern DLSYM_PROTOTYPE(SSL_get_error);
extern DLSYM_PROTOTYPE(SSL_get_wbio);
extern DLSYM_PROTOTYPE(SSL_get0_param);
extern DLSYM_PROTOTYPE(SSL_get1_session);
extern DLSYM_PROTOTYPE(SSL_new);
extern DLSYM_PROTOTYPE(SSL_read);
extern DLSYM_PROTOTYPE(SSL_SESSION_free);
extern DLSYM_PROTOTYPE(SSL_set_bio);
extern DLSYM_PROTOTYPE(SSL_set_connect_state);
extern DLSYM_PROTOTYPE(SSL_set_session);
extern DLSYM_PROTOTYPE(SSL_set_verify);
extern DLSYM_PROTOTYPE(SSL_shutdown);
extern DLSYM_PROTOTYPE(SSL_write);
extern DLSYM_PROTOTYPE(TLS_client_method);

/* Mirrors of OpenSSL macros that go through our dlopen'd sym_* variants, so we don't end up linking against
 * libssl just for these. */
#define sym_SSL_set_tlsext_host_name(s, name) \
        sym_SSL_ctrl((s), SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void *) (name))
#define sym_SSL_CTX_set_min_proto_version(ctx, version) \
        sym_SSL_CTX_ctrl((ctx), SSL_CTRL_SET_MIN_PROTO_VERSION, (version), NULL)

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(SSL*, sym_SSL_free, SSL_freep, NULL);

#endif
