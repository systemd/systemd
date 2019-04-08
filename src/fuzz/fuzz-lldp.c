/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-lldp.h"

#include "fd-util.h"
#include "fuzz.h"
#include "lldp-network.h"

static int test_fd[2] = { -1, -1 };

int lldp_network_bind_raw_socket(int ifindex) {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_lldp_unrefp) sd_lldp *lldp = NULL;

        if (size > 2048)
                return 0;

        assert_se(sd_event_new(&e) == 0);
        assert_se(sd_lldp_new(&lldp) >= 0);
        assert_se(sd_lldp_set_ifindex(lldp, 42) >= 0);
        assert_se(sd_lldp_attach_event(lldp, e, 0) >= 0);
        assert_se(sd_lldp_start(lldp) >= 0);

        assert_se(write(test_fd[1], data, size) == (ssize_t) size);
        assert_se(sd_event_run(e, 0) >= 0);

        assert_se(sd_lldp_stop(lldp) >= 0);
        assert_se(sd_lldp_detach_event(lldp) >= 0);
        test_fd[1] = safe_close(test_fd[1]);

        return 0;
}
