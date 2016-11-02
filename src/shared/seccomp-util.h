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

const char* seccomp_arch_to_string(uint32_t c);
int seccomp_arch_from_string(const char *n, uint32_t *ret);

int seccomp_init_conservative(scmp_filter_ctx *ret, uint32_t default_action);

int seccomp_add_secondary_archs(scmp_filter_ctx c);

bool is_seccomp_available(void);

typedef struct SyscallFilterSet {
        const char *name;
        const char *value;
} SyscallFilterSet;

enum {
        SYSCALL_FILTER_SET_BASIC_IO,
        SYSCALL_FILTER_SET_CLOCK,
        SYSCALL_FILTER_SET_CPU_EMULATION,
        SYSCALL_FILTER_SET_DEBUG,
        SYSCALL_FILTER_SET_DEFAULT,
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
        SYSCALL_FILTER_SET_RESOURCES,
        _SYSCALL_FILTER_SET_MAX
};

extern const SyscallFilterSet syscall_filter_sets[];

const SyscallFilterSet *syscall_filter_set_find(const char *name);

int seccomp_add_syscall_filter_set(scmp_filter_ctx seccomp, const SyscallFilterSet *set, uint32_t action);

int seccomp_load_filter_set(uint32_t default_action, const SyscallFilterSet *set, uint32_t action);
