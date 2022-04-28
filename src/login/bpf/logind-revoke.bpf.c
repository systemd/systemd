/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/hidraw.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern int hid_bpf_hidraw_revoke(int fd) __ksym;

struct hidraw_revoke_syscall_args {
       int fd;
};

SEC("syscall")
int hidraw_revoke(struct hidraw_revoke_syscall_args *args)
{
       return hid_bpf_hidraw_revoke(args->fd);
}

char LICENSE[] SEC("license") = "GPL";
