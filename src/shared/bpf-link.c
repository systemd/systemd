/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "serialize.h"

bool bpf_can_link_program(struct bpf_program *prog) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;

        assert(prog);

        if (dlopen_bpf(LOG_DEBUG) < 0)
                return false;

        /* Pass invalid cgroup fd intentionally. */
        link = sym_bpf_program__attach_cgroup(prog, /* cgroup_fd= */ -1);

        /* EBADF indicates that bpf_link is supported by kernel. */
        return bpf_get_error_translated(link) == -EBADF;
}

bool bpf_can_link_lsm_program(struct bpf_program *prog) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;

        assert(prog);

        if (dlopen_bpf(LOG_DEBUG) < 0)
                return false;

        link = sym_bpf_program__attach_lsm(prog);

        /* If bpf_program__attach_lsm fails the resulting value stores libbpf error code instead of memory
         * pointer. That is the case when the helper is called on architectures where BPF trampoline (hence
         * BPF_LSM_MAC attach type) is not supported. */
        return bpf_get_error_translated(link) == 0;
}

int bpf_serialize_link(FILE *f, FDSet *fds, const char *key, struct bpf_link *link) {
        assert(key);

        if (!link)
                return -ENOENT;

        if (bpf_get_error_translated(link) != 0)
                return -EINVAL;

        return serialize_fd(f, fds, key, sym_bpf_link__fd(link));
}

struct bpf_link* bpf_link_free(struct bpf_link *link) {
        /* If libbpf wasn't dlopen()ed, sym_bpf_link__destroy might be unresolved (NULL), so let's not try to
         * call it if link is NULL. link might also be a non-null "error pointer", but such a value can only
         * originate from a call to libbpf, but that means that libbpf is available, and we can let
         * bpf_link__destroy() handle it. */
        if (link)
                (void) sym_bpf_link__destroy(link);

        return NULL;
}

struct ring_buffer* bpf_ring_buffer_free(struct ring_buffer *rb) {
        if (rb) /* See the comment in bpf_link_free(). */
                sym_ring_buffer__free(rb);

        return NULL;
}
