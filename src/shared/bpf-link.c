/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LIBBPF
#include <bpf/libbpf.h>
#endif

#include "bpf-link.h"
#include "serialize.h"

#if HAVE_LIBBPF
bool can_link_bpf_program(BpfProgram *prog) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;

        assert(prog);

        /* Pass invalid cgroup fd intentionally. */
        link = bpf_program__attach_cgroup(prog, /*cgroup_fd=*/-1);

        /* EBADF indicates that bpf_link is supported by kernel. */
        return libbpf_get_error(link) == -EBADF;
}

int serialize_bpf_link(FILE *f, FDSet *fds, const char *key, BpfLink *link) {
        int fd;

        assert(key);
        assert(link);
        if (libbpf_get_error(link) != 0)
                return -EINVAL;

        fd = bpf_link__fd(link);
        return serialize_fd(f, fds, key, fd);
}

BpfLink *bpf_link_free(BpfLink *link) {
        /* bpf_link__destroy handles link == NULL case */
       (void) bpf_link__destroy(link);

        return NULL;
}
#else
bool can_link_bpf_program(BpfProgram *prog) {
        return false;
}

int serialize_bpf_link(FILE *f, FDSet *fds, const char *key, BpfLink *link) {
        return 0;
}

BpfLink *bpf_link_free(BpfLink *link) {
        return NULL;
}
#endif
