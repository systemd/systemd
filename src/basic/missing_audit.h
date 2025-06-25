/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/audit.h>        /* IWYU pragma: export */

#if HAVE_AUDIT
#  include <libaudit.h>         /* IWYU pragma: export */
#endif

/* We use _Static_assert() directly here instead of assert_cc()
 * because if we include macro.h in this header, the invocation
 * of generate-audit_type-list.sh becomes more complex.
 */

#ifndef AUDIT_SERVICE_START
#  define AUDIT_SERVICE_START 1130 /* Service (daemon) start */
#else
_Static_assert(AUDIT_SERVICE_START == 1130, "");
#endif

#ifndef AUDIT_SERVICE_STOP
#  define AUDIT_SERVICE_STOP 1131 /* Service (daemon) stop */
#else
_Static_assert(AUDIT_SERVICE_STOP == 1131, "");
#endif

#ifndef MAX_AUDIT_MESSAGE_LENGTH
#  define MAX_AUDIT_MESSAGE_LENGTH 8970
#else
_Static_assert(MAX_AUDIT_MESSAGE_LENGTH == 8970, "");
#endif
