/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LIBBPF
#include <bpf/libbpf.h>
#endif

#include "bpf-link.h"

#if HAVE_LIBBPF
BPFLink *bpf_link_free(BPFLink *link) {
        if (link && libbpf_get_error(link) == 0)
               (void) bpf_link__destroy(link);

        return NULL;
}
#else
BPFLink *bpf_link_free(BPFLink *link) {
        return NULL;
}
#endif
