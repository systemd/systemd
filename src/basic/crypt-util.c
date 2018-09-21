/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LIBCRYPTSETUP
#include "crypt-util.h"
#include "log.h"

void cryptsetup_log_glue(int level, const char *msg, void *usrptr) {
        switch (level) {
        case CRYPT_LOG_NORMAL:
                level = LOG_NOTICE;
                break;
        case CRYPT_LOG_ERROR:
                level = LOG_ERR;
                break;
        case CRYPT_LOG_VERBOSE:
                level = LOG_INFO;
                break;
        case CRYPT_LOG_DEBUG:
                level = LOG_DEBUG;
                break;
        default:
                log_error("Unknown libcryptsetup log level: %d", level);
                level = LOG_ERR;
        }

        log_full(level, "%s", msg);
}
#endif
