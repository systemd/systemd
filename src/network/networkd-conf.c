/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Vinay Kulkarni <kulkarniv@vmware.com>
 ***/

#include "conf-parser.h"
#include "errno-util.h"
#include "networkd-address-label.h"
#include "networkd-conf.h"
#include "networkd-manager.h"
#include "networkd-route.h"
#include "networkd-speed-meter.h"

int manager_parse_config_file(Manager *m) {
        int r;

        assert(m);

        r = config_parse_standard_file_with_dropins(
                        "systemd/networkd.conf",
                        "Network\0"
                        "IPv6AcceptRA\0"
                        "IPv6AddressLabel\0"
                        "Route\0"
                        "DHCPv4\0"
                        "DHCPv6\0"
                        "DHCPServer\0"
                        "DHCPRelay\0"
                        "DHCP\0",
                        config_item_perf_lookup, networkd_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ m);

        /* Even on failure, some sections may have been loaded, hence they always need to be verified. */
        manager_drop_invalid_address_labels(m);
        RET_GATHER(r, manager_drop_invalid_routes(m));
        if (r < 0)
                return r;

        if (m->use_speed_meter && m->speed_meter_interval_usec < SPEED_METER_MINIMUM_TIME_INTERVAL) {
                log_warning("SpeedMeterIntervalSec= is too small, using %s.",
                            FORMAT_TIMESPAN(SPEED_METER_MINIMUM_TIME_INTERVAL, USEC_PER_SEC));
                m->speed_meter_interval_usec = SPEED_METER_MINIMUM_TIME_INTERVAL;
        }

        return 0;
}
