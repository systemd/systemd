/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <unistd.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "icmp6-util-unix.h"
#include "ndisc-internal.h"
#include "socket-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        struct ether_addr mac_addr = {
                .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
        };
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        if (outside_size_range(size, 0, 2048))
                return 0;

        fuzz_setup_logging();

        assert_se(sd_event_new(&e) >= 0);
        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);
        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);
        assert_se(sd_ndisc_start(nd) >= 0);
        assert_se(write(test_fd[1], data, size) == (ssize_t) size);
        (void) sd_event_run(e, UINT64_MAX);
        assert_se(sd_ndisc_stop(nd) >= 0);
        close(test_fd[1]);

        return 0;
}
