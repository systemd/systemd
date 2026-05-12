/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mempolicy.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef set_mempolicy
extern typeof(missing_set_mempolicy) set_mempolicy;
#pragma weak set_mempolicy
int missing_set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode) {
        if (set_mempolicy)
                return set_mempolicy(mode, nodemask, maxnode);
        return syscall(__NR_set_mempolicy, mode, nodemask, maxnode);
}

#undef get_mempolicy
extern typeof(missing_get_mempolicy) get_mempolicy;
#pragma weak get_mempolicy
int missing_get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags) {
        if (get_mempolicy)
                return get_mempolicy(mode, nodemask, maxnode, addr, flags);
        return syscall(__NR_get_mempolicy, mode, nodemask, maxnode, addr, flags);
}
