/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "serialize.h"

bool can_link_bpf_program(struct bpf_program *prog) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
        int r;

        assert(prog);

        r = dlopen_bpf();
        if (r < 0) {
                log_debug_errno(r, "Could not load libbpf: %m");
                return false;
        }

        /* Pass invalid cgroup fd intentionally. */
        link = sym_bpf_program__attach_cgroup(prog, /*cgroup_fd=*/-1);

        /* EBADF indicates that bpf_link is supported by kernel. */
        return sym_libbpf_get_error(link) == -EBADF;
}

int serialize_bpf_link(FILE *f, FDSet *fds, const char *key, struct bpf_link *link) {
        int fd;

        assert(key);

        if (!link)
                return -ENOENT;

        if (sym_libbpf_get_error(link) != 0)
                return -EINVAL;

        fd = sym_bpf_link__fd(link);
        return serialize_fd(f, fds, key, fd);
}

struct bpf_link *bpf_link_free(struct bpf_link *link) {
        /* Avoid a useless dlopen() if link == NULL */
        if (!link)
                return NULL;

        (void) sym_bpf_link__destroy(link);

        return NULL;
}
