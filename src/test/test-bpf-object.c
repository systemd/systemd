/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <bpf/bpf.h>
#include <sys/resource.h>

#include "architecture.h"
#include "bpf-object.h"
#include "bpf/allow_bind/allow-bind-hexdump.h"
#include "set.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        _cleanup_(bpf_object_freep) struct bpf_object *obj = NULL;
        Set *progs = NULL;
        uint8_t dummy = 1;
        struct rlimit rl;
        uint16_t key;
        int r, fd;

        assert_se(getrlimit(RLIMIT_MEMLOCK, &rl) >= 0);
        rl.rlim_cur = rl.rlim_max = MAX(rl.rlim_max, CAN_MEMLOCK_SIZE);
        (void) setrlimit(RLIMIT_MEMLOCK, &rl);

        if (!can_memlock())
                return log_tests_skipped("Can't use mlock(), skipping.");

        if (!bpf_probe_prog_type(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, /*ifindex=*/0))
                return log_tests_skipped("BPF program type cgroup_sock_addr is not supported.");

        r = bpf_object_new(allow_bind_hexdump_buffer, sizeof(allow_bind_hexdump_buffer), &obj);
        assert_se(r == 0);

        r = bpf_object_load(obj);
        assert_se(r >= 0);

        r = bpf_object_get_programs(obj, &progs);
        assert_se(r >= 0);

        assert_se(set_size(progs) == 2);

        bpf_object_resize_map(obj, "allow_ports", 128);
        assert_se(r >= 0);

        fd = bpf_object_get_map_fd(obj, "allow_ports");
        assert_se(fd >= 0);

        r = bpf_map_update_elem(fd, &key, &dummy, BPF_ANY);
        assert_se(r == 0);

        return 0;
}
