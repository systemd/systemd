/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-lldp-rx.h"

#include "fd-util.h"
#include "fuzz.h"
#include "lldp-network.h"
#include "lldp-rx-internal.h"
#include "memstream-util.h"

static int test_fd[2] = EBADF_PAIR;

int lldp_network_bind_raw_socket(int ifindex) {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_lldp_rx_unrefp) sd_lldp_rx *lldp_rx = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;

        if (outside_size_range(size, 0, 2048))
                return 0;

        fuzz_setup_logging();

        assert_se(sd_event_new(&e) == 0);
        assert_se(sd_lldp_rx_new(&lldp_rx) >= 0);
        assert_se(sd_lldp_rx_set_ifindex(lldp_rx, 42) >= 0);
        assert_se(sd_lldp_rx_attach_event(lldp_rx, e, 0) >= 0);
        assert_se(sd_lldp_rx_start(lldp_rx) >= 0);

        assert_se(write(test_fd[1], data, size) == (ssize_t) size);
        assert_se(sd_event_run(e, 0) >= 0);

        assert_se(lldp_rx_build_neighbors_json(lldp_rx, &v) >= 0);
        assert_se(f = memstream_init(&m));
        (void) sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR, f, NULL);

        assert_se(sd_lldp_rx_stop(lldp_rx) >= 0);
        assert_se(sd_lldp_rx_detach_event(lldp_rx) >= 0);
        test_fd[1] = safe_close(test_fd[1]);

        return 0;
}
