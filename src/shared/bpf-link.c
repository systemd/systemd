/* SPDX-License-Identifier: LGPL-2.1+ */

#include <bpf/libbpf.h>

#include "bpf-link.h"
#include "serialize.h"

bool can_link_bpf_program(struct bpf_program *prog) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;

        assert(prog);

        /* Pass invalid cgroup fd intentionally. */
        link = bpf_program__attach_cgroup(prog, /*cgroup_fd=*/-1);

        /* EBADF indicates that bpf_link is supported by kernel. */
        return libbpf_get_error(link) == -EBADF;
}

int serialize_bpf_link(FILE *f, FDSet *fds, const char *key, struct bpf_link *link) {
        int fd;

        assert(key);

        if (!link)
                return -ENOENT;

        if (libbpf_get_error(link) != 0)
                return -EINVAL;

        fd = bpf_link__fd(link);
        return serialize_fd(f, fds, key, fd);
}

struct bpf_link *bpf_link_free(struct bpf_link *link) {
        /* bpf_link__destroy handles link == NULL case */
        (void) bpf_link__destroy(link);

        return NULL;
}
