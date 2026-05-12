/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mempolicy.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef set_mempolicy
extern typeof(set_mempolicy_shim) set_mempolicy __attribute__((weak));
int set_mempolicy_shim(int mode, const unsigned long *nodemask, unsigned long maxnode) {
        if (set_mempolicy)
                return set_mempolicy(mode, nodemask, maxnode);
        return syscall(__NR_set_mempolicy, mode, nodemask, maxnode);
}

#undef get_mempolicy
extern typeof(get_mempolicy_shim) get_mempolicy __attribute__((weak));
int get_mempolicy_shim(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags) {
        if (get_mempolicy)
                return get_mempolicy(mode, nodemask, maxnode, addr, flags);
        return syscall(__NR_get_mempolicy, mode, nodemask, maxnode, addr, flags);
}
