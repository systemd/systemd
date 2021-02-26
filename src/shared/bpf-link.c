/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LIBBPF
#include <bpf/libbpf.h>
#endif

#include "bpf-link.h"

#if HAVE_LIBBPF
int serialize_bpf_link(FILE *f, FDSet *fds, const char *key, BPFLink *link) {
        int fd;

        assert(key);
        assert(link);

        fd = bpf_link__fd(link);
        if (fd < 0)
                return -errno;

        return serialize_fd(f, fds, key, fd);
}

BPFLink *bpf_link_free(BPFLink *link) {
        if (link && libbpf_get_error(link) == 0)
               (void) bpf_link__destroy(link);

        return NULL;
}
#else
int serialize_bpf_link(FILE *f, FDSet *fds, const char *key, BPFLink *link) {
        return 0;
}
BPFLink *bpf_link_free(BPFLink *link) {
        return NULL;
}
#endif
