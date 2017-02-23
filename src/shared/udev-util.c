/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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

        r = parse_env_file("/etc/udev/udev.conf", NEWLINE, "udev_log", &val, NULL);
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
