/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* <linux/bpf.h> must precede <bpf/bpf_helpers.h> due to integer types
 * in bpf helpers signatures.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* VRF interface index to bind sockets to, set from userspace */
const volatile __u32 ifindex = 0;

SEC("cgroup/sock_create")
int sd_bind_interface(struct bpf_sock *ctx) {
        /* Bind the socket to the VRF interface */
        ctx->bound_dev_if = ifindex;
        return 1;
}

static const char _license[] SEC("license") = "LGPL-2.1-or-later";
