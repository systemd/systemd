/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <bpf/bpf.h>
#include <fcntl.h>

#include "alloc-util.h"
#include "bpf-program-v2.h"
#include "fd-util.h"
#include "memory-util.h"

int bpf_program_v2_new(int fd, enum bpf_attach_type attach_type, BPFProgramV2 **ret) {
        _cleanup_(bpf_program_v2_freep) BPFProgramV2 *p = NULL;

        assert(ret);

        p = new(BPFProgramV2, 1);
        if (!p)
                return -ENOMEM;

        *p = (BPFProgramV2) {
                .fd = fd,
                .attach_type = attach_type,
        };

        *ret = TAKE_PTR(p);

        return 0;
}

BPFProgramV2 *bpf_program_v2_free(BPFProgramV2 *p) {
        if (p)
                safe_close(p->fd);

        return mfree(p);
}

int bpf_program_v2_cgroup_attach(const BPFProgramV2 *p, const char *cgroup_path, uint32_t attach_flags) {
        _cleanup_close_ int cgroup_fd = -1;

        assert(p);
        assert(cgroup_path);

        cgroup_fd = open(cgroup_path, O_RDONLY | O_CLOEXEC, 0);
        if (cgroup_fd < 0)
                return -errno;

        if (bpf_prog_attach(p->fd, cgroup_fd, p->attach_type, attach_flags))
                return -errno;

        return 0;
}

int bpf_program_v2_cgroup_detach(const BPFProgramV2 *p, const char *cgroup_path) {
        _cleanup_close_ int cgroup_fd = -1;

        assert(p);
        assert(cgroup_path);

        cgroup_fd = open(cgroup_path, O_RDONLY | O_CLOEXEC, 0);
        if (cgroup_fd < 0)
                return -errno;

        if (bpf_prog_detach2(p->fd, cgroup_fd, p->attach_type))
                return -errno;

        return 0;
}
