/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "networkd-manager.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_tempfilep) char netdev_config[] = "/tmp/fuzz-networkd.XXXXXX";
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;

        if (outside_size_range(size, 0, 65536))
                return 0;

        fuzz_setup_logging();

        assert_se(fmkostemp_safe(netdev_config, "r+", &f) == 0);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);

        fflush(f);
        assert_se(manager_new(&manager, /* test_mode = */ true) >= 0);
        (void) netdev_load_one(manager, netdev_config, &netdev);
        return 0;
}
