/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "serialize.h"

bool bpf_can_link_program(struct bpf_program *prog) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;

        assert(prog);

        if (dlopen_bpf() < 0)
                return false;

        /* Pass invalid cgroup fd intentionally. */
        link = sym_bpf_program__attach_cgroup(prog, /*cgroup_fd=*/-1);

        /* EBADF indicates that bpf_link is supported by kernel. */
        return sym_libbpf_get_error(link) == -EBADF;
}

int bpf_serialize_link(FILE *f, FDSet *fds, const char *key, struct bpf_link *link) {
        assert(key);

        if (!link)
                return -ENOENT;

        if (sym_libbpf_get_error(link) != 0)
                return -EINVAL;

        return serialize_fd(f, fds, key, sym_bpf_link__fd(link));
}

struct bpf_link *bpf_link_free(struct bpf_link *link) {

        /* Avoid a useless dlopen() if link == NULL */
        if (!link)
                return NULL;

        (void) sym_bpf_link__destroy(link);

        return NULL;
}
