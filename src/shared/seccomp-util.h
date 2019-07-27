/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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
        SYSCALL_FILTER_SET_AIO,
        SYSCALL_FILTER_SET_BASIC_IO,
        SYSCALL_FILTER_SET_CHOWN,
        SYSCALL_FILTER_SET_CLOCK,
        SYSCALL_FILTER_SET_CPU_EMULATION,
        SYSCALL_FILTER_SET_DEBUG,
        SYSCALL_FILTER_SET_FILE_SYSTEM,
        SYSCALL_FILTER_SET_IO_EVENT,
        SYSCALL_FILTER_SET_IPC,
        SYSCALL_FILTER_SET_KEYRING,
        SYSCALL_FILTER_SET_MEMLOCK,
        SYSCALL_FILTER_SET_MODULE,
        SYSCALL_FILTER_SET_MOUNT,
        SYSCALL_FILTER_SET_NETWORK_IO,
        SYSCALL_FILTER_SET_OBSOLETE,
        SYSCALL_FILTER_SET_PRIVILEGED,
        SYSCALL_FILTER_SET_PROCESS,
        SYSCALL_FILTER_SET_RAW_IO,
        SYSCALL_FILTER_SET_REBOOT,
        SYSCALL_FILTER_SET_RESOURCES,
        SYSCALL_FILTER_SET_SETUID,
        SYSCALL_FILTER_SET_SIGNAL,
        SYSCALL_FILTER_SET_SWAP,
        SYSCALL_FILTER_SET_SYNC,
        SYSCALL_FILTER_SET_SYSTEM_SERVICE,
        SYSCALL_FILTER_SET_TIMER,
        _SYSCALL_FILTER_SET_MAX
};

extern const SyscallFilterSet syscall_filter_sets[];

const SyscallFilterSet *syscall_filter_set_find(const char *name);

int seccomp_filter_set_add(Hashmap *s, bool b, const SyscallFilterSet *set);

int seccomp_add_syscall_filter_item(scmp_filter_ctx *ctx, const char *name, uint32_t action, char **exclude, bool log_missing);

int seccomp_load_syscall_filter_set(uint32_t default_action, const SyscallFilterSet *set, uint32_t action, bool log_missing);
int seccomp_load_syscall_filter_set_raw(uint32_t default_action, Hashmap* set, uint32_t action, bool log_missing);

typedef enum SeccompParseFlags {
        SECCOMP_PARSE_INVERT     = 1 << 0,
        SECCOMP_PARSE_WHITELIST  = 1 << 1,
        SECCOMP_PARSE_LOG        = 1 << 2,
        SECCOMP_PARSE_PERMISSIVE = 1 << 3,
} SeccompParseFlags;

int seccomp_parse_syscall_filter(
                const char *name,
                int errno_num,
                Hashmap *filter,
                SeccompParseFlags flags,
                const char *unit,
                const char *filename, unsigned line);

int seccomp_restrict_archs(Set *archs);
int seccomp_restrict_namespaces(unsigned long retain);
int seccomp_protect_sysctl(void);
int seccomp_restrict_address_families(Set *address_families, bool whitelist);
int seccomp_restrict_realtime(void);
int seccomp_memory_deny_write_execute(void);
int seccomp_lock_personality(unsigned long personality);
int seccomp_protect_hostname(void);
int seccomp_restrict_suid_sgid(void);

extern const uint32_t seccomp_local_archs[];

#define SECCOMP_FOREACH_LOCAL_ARCH(arch) \
        for (unsigned _i = ({ (arch) = seccomp_local_archs[0]; 0; });   \
             seccomp_local_archs[_i] != (uint32_t) -1;                  \
             (arch) = seccomp_local_archs[++_i])

/* EACCES: does not have the CAP_SYS_ADMIN or no_new_privs == 1
 * ENOMEM: out of memory, failed to allocate space for a libseccomp structure, or would exceed a defined constant
 * EFAULT: addresses passed as args (by libseccomp) are invalid */
#define ERRNO_IS_SECCOMP_FATAL(r)                                       \
        IN_SET(abs(r), EPERM, EACCES, ENOMEM, EFAULT)

DEFINE_TRIVIAL_CLEANUP_FUNC(scmp_filter_ctx, seccomp_release);

int parse_syscall_archs(char **l, Set **archs);

uint32_t scmp_act_kill_process(void);
