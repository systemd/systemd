/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-dump.h"
#include "cgroup-setup.h"
#include "errno-util.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        int r;

        test_setup_logging(LOG_DEBUG);

        if (cg_is_ready() <= 0)
                return log_tests_skipped("/sys/fs/cgroup/ not available");

        r = sd_bus_creds_new_from_pid(&creds, 0, _SD_BUS_CREDS_ALL);
        log_full_errno(r < 0 ? LOG_ERR : LOG_DEBUG, r, "sd_bus_creds_new_from_pid: %m");
        assert_se(r >= 0);

        bus_creds_dump(creds, NULL, true);

        creds = sd_bus_creds_unref(creds);

        r = sd_bus_creds_new_from_pid(&creds, 1, _SD_BUS_CREDS_ALL);
        if (!ERRNO_IS_NEG_PRIVILEGE(r)) {
                assert_se(r >= 0);
                putchar('\n');
                bus_creds_dump(creds, NULL, true);
        }

        creds = sd_bus_creds_unref(creds);

        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        r = sd_bus_default_system(&bus);
        if (r < 0)
                log_warning_errno(r, "Unable to connect to system bus, skipping rest of test.");
        else {
                const char *unique;

                assert_se(sd_bus_get_unique_name(bus, &unique) >= 0);

                r = sd_bus_get_name_creds(bus, unique, _SD_BUS_CREDS_ALL, &creds);
                log_full_errno(r < 0 ? LOG_ERR : LOG_DEBUG, r, "sd_bus_get_name_creds: %m");
                assert_se(r >= 0);

                putchar('\n');
                bus_creds_dump(creds, NULL, true);
        }

        return 0;
}
