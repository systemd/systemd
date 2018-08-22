/* SPDX-License-Identifier: LGPL-2.1+ */

#include <string.h>

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

int udev_device_new_from_stat_rdev(struct udev *udev, const struct stat *st, struct udev_device **ret) {
        struct udev_device *nd;
        char type;

        assert(st);
        assert(ret);

        if (S_ISBLK(st->st_mode))
                type = 'b';
        else if (S_ISCHR(st->st_mode))
                type = 'c';
        else
                return -ENOTTY;

        nd = udev_device_new_from_devnum(udev, type, st->st_rdev);
        if (!nd)
                return -errno;

        *ret = nd;
        return 0;
}
