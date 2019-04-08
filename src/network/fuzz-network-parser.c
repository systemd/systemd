/* SPDX-License-Identifier: LGPL-2.1+ */

#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "networkd-manager.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_tempfilep) char network_config[] = "/tmp/fuzz-networkd.XXXXXX";

        if (size > 65535)
                return 0;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        assert_se(fmkostemp_safe(network_config, "r+", &f) == 0);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);

        fflush(f);
        assert_se(manager_new(&manager) >= 0);
        (void) network_load_one(manager, network_config);
        return 0;
}
