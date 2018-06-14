/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LIBCRYPTSETUP
#include "crypt-util.h"
#include "log.h"

void cryptsetup_log_glue(int level, const char *msg, void *usrptr) {
        log_debug("%s", msg);
}
#endif
