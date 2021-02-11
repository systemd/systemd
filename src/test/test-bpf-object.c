/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <bpf/bpf.h>
#include <sys/resource.h>
#include <unistd.h>

#include "architecture.h"
#include "bpf-object.h"
#include "bpf/restrict_fs/restrict-fs-hexdump.h"

#include "set.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        _cleanup_(bpf_object_freep) struct bpf_object *obj = NULL;
        struct rlimit rl;
        int r, fd, inner_fd;
        uint64_t dummy = 1;

        assert_se(getrlimit(RLIMIT_MEMLOCK, &rl) >= 0);
        rl.rlim_cur = rl.rlim_max = MAX(rl.rlim_max, CAN_MEMLOCK_SIZE);
        (void) setrlimit(RLIMIT_MEMLOCK, &rl);

        if (!can_memlock())
                return log_tests_skipped("Can't use mlock(), skipping.");

        r = bpf_object_new(restrict_fs_hexdump_buffer, sizeof(restrict_fs_hexdump_buffer), &obj);
        assert_se(r == 0);

        inner_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u32), 128, 0);
        assert_se(inner_fd >= 0);

        r = bpf_object_set_inner_map_fd(obj, "cgroup_hash", inner_fd);
        assert_se(r >= 0);

        r = bpf_object_load(obj);
        assert_se(r >= 0);

        close(inner_fd);

        fd = bpf_object_get_map_fd(obj, "cgroup_hash");
        assert_se(fd >= 0);

        inner_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u32), 128, 0);

        r = bpf_map_update_elem(fd, &dummy, &inner_fd, BPF_ANY);
        assert_se(r == 0);

        return 0;
}
