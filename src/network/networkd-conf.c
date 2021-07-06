/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Vinay Kulkarni <kulkarniv@vmware.com>
 ***/

#include "conf-parser.h"
#include "def.h"
#include "networkd-conf.h"
#include "networkd-manager.h"
#include "networkd-speed-meter.h"

int manager_parse_config_file(Manager *m) {
        int r;

        assert(m);

        r = config_parse_many_nulstr(
                        PKGSYSCONFDIR "/networkd.conf",
                        CONF_PATHS_NULSTR("systemd/networkd.conf.d"),
                        "Network\0"
                        "DHCPv4\0"
                        "DHCPv6\0"
                        "DHCP\0",
                        config_item_perf_lookup, networkd_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        m,
                        NULL);
        if (r < 0)
                return r;

        if (m->use_speed_meter && m->speed_meter_interval_usec < SPEED_METER_MINIMUM_TIME_INTERVAL) {
                log_warning("SpeedMeterIntervalSec= is too small, using %s.",
                            FORMAT_TIMESPAN(SPEED_METER_MINIMUM_TIME_INTERVAL, USEC_PER_SEC));
                m->speed_meter_interval_usec = SPEED_METER_MINIMUM_TIME_INTERVAL;
        }

        return 0;
}
