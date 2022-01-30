/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-lease-internal.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "network-internal.h"
#include "tmpfile-util.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-lease-load.XXXXXX";
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        _cleanup_close_ int fd = -1;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, data, size) == (ssize_t) size);
        (void) dhcp_lease_load(&lease, name);
        return 0;
}
