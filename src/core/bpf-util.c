/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bpf-dlopen.h"
#include "bpf-util.h"
#include "cgroup-util.h"
#include "initrd-util.h"
#include "log.h"

bool cgroup_bpf_supported(void) {
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;

        r = dlopen_bpf();
        if (r < 0) {
                log_full_errno(in_initrd() ? LOG_DEBUG : LOG_INFO,
                               r, "Failed to open libbpf, cgroup BPF features disabled: %m");
                return (supported = false);
        }

        return (supported = true);
}
