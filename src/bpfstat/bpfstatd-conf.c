/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "constants.h"
#include "bpfstatd-conf.h"

int manager_parse_config_file(Manager *m) {

        assert(m);

        return config_parse_standard_file_with_dropins(
                        "bpfstatd.conf",
                        "BPFStat\0",
                        config_item_perf_lookup, bpfstatd_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        m);
}
