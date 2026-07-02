/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int dlopen_libaudit(int log_level);

#if HAVE_AUDIT
#  ifndef SYSTEMD_CFLAGS_MARKER_LIBAUDIT
#    error("missing libaudit_cflags in meson dependency.");
#  endif

#  include <libaudit.h>         /* IWYU pragma: export */

#  include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(audit_log_acct_message);
extern DLSYM_PROTOTYPE(audit_log_user_avc_message);
extern DLSYM_PROTOTYPE(audit_log_user_comm_message);
#endif

/* libaudit.h defines these constants.
 * Define them here too so they can be used even when libaudit.h is unavailable. */
#ifndef AUDIT_SERVICE_START
#  define AUDIT_SERVICE_START 1130 /* Service (daemon) start */
#else
assert_cc(AUDIT_SERVICE_START == 1130);
#endif

#ifndef AUDIT_SERVICE_STOP
#  define AUDIT_SERVICE_STOP 1131 /* Service (daemon) stop */
#else
assert_cc(AUDIT_SERVICE_STOP == 1131);
#endif

#ifndef MAX_AUDIT_MESSAGE_LENGTH
#  define MAX_AUDIT_MESSAGE_LENGTH 8970
#else
assert_cc(MAX_AUDIT_MESSAGE_LENGTH == 8970);
#endif

bool use_audit(void);

int close_audit_fd(int fd);
int open_audit_fd_or_warn(void);
