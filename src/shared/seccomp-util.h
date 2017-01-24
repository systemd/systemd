#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>

#include "set.h"

const char* seccomp_arch_to_string(uint32_t c);
int seccomp_arch_from_string(const char *n, uint32_t *ret);

int seccomp_init_for_arch(scmp_filter_ctx *ret, uint32_t arch, uint32_t default_action);

bool is_seccomp_available(void);

typedef struct SyscallFilterSet {
        const char *name;
        const char *help;
        const char *value;
} SyscallFilterSet;

enum {
        /* Please leave DEFAULT first, but sort the rest alphabetically */
        SYSCALL_FILTER_SET_DEFAULT,
        SYSCALL_FILTER_SET_BASIC_IO,
        SYSCALL_FILTER_SET_CLOCK,
        SYSCALL_FILTER_SET_CPU_EMULATION,
        SYSCALL_FILTER_SET_DEBUG,
        SYSCALL_FILTER_SET_FILE_SYSTEM,
        SYSCALL_FILTER_SET_IO_EVENT,
        SYSCALL_FILTER_SET_IPC,
        SYSCALL_FILTER_SET_KEYRING,
        SYSCALL_FILTER_SET_MODULE,
        SYSCALL_FILTER_SET_MOUNT,
        SYSCALL_FILTER_SET_NETWORK_IO,
        SYSCALL_FILTER_SET_OBSOLETE,
        SYSCALL_FILTER_SET_PRIVILEGED,
        SYSCALL_FILTER_SET_PROCESS,
        SYSCALL_FILTER_SET_RAW_IO,
        SYSCALL_FILTER_SET_REBOOT,
        SYSCALL_FILTER_SET_RESOURCES,
        SYSCALL_FILTER_SET_SWAP,
        _SYSCALL_FILTER_SET_MAX
};

extern const SyscallFilterSet syscall_filter_sets[];

const SyscallFilterSet *syscall_filter_set_find(const char *name);

int seccomp_load_syscall_filter_set(uint32_t default_action, const SyscallFilterSet *set, uint32_t action);
int seccomp_load_syscall_filter_set_raw(uint32_t default_action, Set* set, uint32_t action);

int seccomp_restrict_archs(Set *archs);
int seccomp_restrict_namespaces(unsigned long retain);
int seccomp_protect_sysctl(void);
int seccomp_restrict_address_families(Set *address_families, bool whitelist);
int seccomp_restrict_realtime(void);
int seccomp_memory_deny_write_execute(void);

extern const uint32_t seccomp_local_archs[];

#define SECCOMP_FOREACH_LOCAL_ARCH(arch) \
        for (unsigned _i = ({ (arch) = seccomp_local_archs[0]; 0; });   \
             seccomp_local_archs[_i] != (uint32_t) -1;                  \
             (arch) = seccomp_local_archs[++_i])

DEFINE_TRIVIAL_CLEANUP_FUNC(scmp_filter_ctx, seccomp_release);
