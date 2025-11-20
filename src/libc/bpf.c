/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_BPF
int missing_bpf(int cmd, union bpf_attr *attr, size_t size) {
        return syscall(__NR_bpf, cmd, attr, size);
}
#endif
