/* SPDX-License-Identifier: LGPL-2.1+ */

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fuzz.h"
#include "networkd-manager.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_tempfilep) char network_config[] = "/tmp/fuzz-networkd.XXXXXX";

        assert_se(fmkostemp_safe(network_config, "r+", &f) == 0);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);

        rewind(f);
        assert_se(manager_new(&manager) >= 0);
        (void) network_load_one(manager, network_config);
        return 0;
}
