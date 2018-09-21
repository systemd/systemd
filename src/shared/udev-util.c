/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <string.h>

#include "alloc-util.h"
#include "fileio.h"
#include "log.h"
#include "string-util.h"
#include "udev-util.h"

int udev_parse_config(void) {
        _cleanup_free_ char *val = NULL;
        const char *log;
        size_t n;
        int r;

        r = parse_env_file(NULL, "/etc/udev/udev.conf", NEWLINE, "udev_log", &val, NULL);
        if (r == -ENOENT || !val)
                return 0;
        if (r < 0)
                return r;

        /* unquote */
        n = strlen(val);
        if (n >= 2 &&
            ((val[0] == '"' && val[n-1] == '"') ||
             (val[0] == '\'' && val[n-1] == '\''))) {
                val[n - 1] = '\0';
                log = val + 1;
        } else
                log = val;

        /* we set the udev log level here explicitly, this is supposed
         * to regulate the code in libudev/ and udev/. */
        r = log_set_max_level_from_string_realm(LOG_REALM_UDEV, log);
        if (r < 0)
                log_debug_errno(r, "/etc/udev/udev.conf: failed to set udev log level '%s', ignoring: %m", log);

        return 0;
}
