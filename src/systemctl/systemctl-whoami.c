/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "bus-util.h"
#include "errno-util.h"
#include "parse-util.h"
#include "strv.h"
#include "systemctl.h"
#include "systemctl-util.h"
#include "systemctl-whoami.h"

int verb_whoami(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        int r, ret = 0;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        if (argc <= 1) {
                _cleanup_free_ char *unit = NULL;

                if (arg_transport != BUS_TRANSPORT_LOCAL)
                        return log_error_errno(SYNTHETIC_ERRNO(EREMOTE),
                                               "Refusing to look up our local PID on remote host.");

                /* Our own process can never go away while querying, hence no need to go through pidfd. */

                r = get_unit_by_pid(bus, 0, &unit, /* ret_path = */ NULL);
                if (r < 0)
                        return r;

                puts(unit);
                return 0;
        }

        STRV_FOREACH(pidstr, strv_skip(argv, 1)) {
                _cleanup_free_ char *unit = NULL;
                pid_t pid;

                r = parse_pid(*pidstr, &pid);
                if (r < 0)
                        return log_error_errno(r, "Invalid PID specified: %s", *pidstr);

                r = lookup_unit_by_pidref(bus, pid, &unit, /* ret_path = */ NULL);
                if (r < 0)
                        RET_GATHER(ret, r);
                else
                        puts(unit);
        }

        return ret;
}
