/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LIBCRYPTSETUP
#include "crypt-util.h"
#include "log.h"

static void cryptsetup_log_glue(int level, const char *msg, void *usrptr) {
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

void cryptsetup_enable_logging(struct crypt_device *cd) {
        crypt_set_log_callback(cd, cryptsetup_log_glue, NULL);
        crypt_set_debug_level(DEBUG_LOGGING ? CRYPT_DEBUG_ALL : CRYPT_DEBUG_NONE);
}

#endif
