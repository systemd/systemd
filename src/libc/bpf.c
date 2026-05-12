/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef bpf
extern typeof(missing_bpf) bpf __attribute__((weak));
int missing_bpf(int cmd, union bpf_attr *attr, size_t size) {
        if (bpf)
                return bpf(cmd, attr, size);
        return syscall(__NR_bpf, cmd, attr, size);
}
