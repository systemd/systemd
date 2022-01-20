/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fuzz.h"
#include "resolved-etc-hosts.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(etc_hosts_free) EtcHosts h = {};

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        f = data_to_file(data, size);
        assert_se(f);

        (void) etc_hosts_parse(&h, f);

        return 0;
}
