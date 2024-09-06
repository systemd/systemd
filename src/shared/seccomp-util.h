/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_SECCOMP
#include <seccomp.h>
#endif
#include <stdbool.h>
#include <stdint.h>

#include "errno-list.h"
#include "errno-util.h"
#include "parse-util.h"
#include "set.h"
#include "string-util.h"

#if HAVE_SECCOMP

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
        /* Please leave DEFAULT first and KNOWN last, but sort the rest alphabetically */
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
        SYSCALL_FILTER_SET_PKEY,
        SYSCALL_FILTER_SET_PRIVILEGED,
        SYSCALL_FILTER_SET_PROCESS,
        SYSCALL_FILTER_SET_RAW_IO,
        SYSCALL_FILTER_SET_REBOOT,
        SYSCALL_FILTER_SET_RESOURCES,
        SYSCALL_FILTER_SET_SANDBOX,
        SYSCALL_FILTER_SET_SETUID,
        SYSCALL_FILTER_SET_SIGNAL,
        SYSCALL_FILTER_SET_SWAP,
        SYSCALL_FILTER_SET_SYNC,
        SYSCALL_FILTER_SET_SYSTEM_SERVICE,
        SYSCALL_FILTER_SET_TIMER,
        SYSCALL_FILTER_SET_KNOWN,
        _SYSCALL_FILTER_SET_MAX,
};

assert_cc(SYSCALL_FILTER_SET_DEFAULT == 0);
assert_cc(SYSCALL_FILTER_SET_KNOWN == _SYSCALL_FILTER_SET_MAX-1);

extern const SyscallFilterSet syscall_filter_sets[];

const SyscallFilterSet *syscall_filter_set_find(const char *name);

int seccomp_filter_set_add_by_name(Hashmap *s, bool b, const char *name);
int seccomp_filter_set_add(Hashmap *s, bool b, const SyscallFilterSet *set);

int seccomp_add_syscall_filter_item(
                scmp_filter_ctx *ctx,
                const char *name,
                uint32_t action,
                char **exclude,
                bool log_missing,
                char ***added);

int seccomp_load_syscall_filter_set(uint32_t default_action, const SyscallFilterSet *set, uint32_t action, bool log_missing);
int seccomp_load_syscall_filter_set_raw(uint32_t default_action, Hashmap* set, uint32_t action, bool log_missing);

typedef enum SeccompParseFlags {
        SECCOMP_PARSE_INVERT     = 1 << 0,
        SECCOMP_PARSE_ALLOW_LIST = 1 << 1,
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
int seccomp_protect_syslog(void);
int seccomp_restrict_address_families(Set *address_families, bool allow_list);
int seccomp_restrict_realtime_full(int error_code); /* This is mostly for testing code. */
static inline int seccomp_restrict_realtime(void) {
        return seccomp_restrict_realtime_full(EPERM);
}
int seccomp_memory_deny_write_execute(void);
int seccomp_lock_personality(unsigned long personality);
int seccomp_protect_hostname(void);
int seccomp_restrict_suid_sgid(void);

extern uint32_t seccomp_local_archs[];

#define SECCOMP_LOCAL_ARCH_END UINT32_MAX

/* Note: 0 is safe to use here because although SCMP_ARCH_NATIVE is 0, it would
 * never be in the seccomp_local_archs array anyway so we can use it as a
 * marker. */
#define SECCOMP_LOCAL_ARCH_BLOCKED 0

#define SECCOMP_FOREACH_LOCAL_ARCH(arch) \
        for (unsigned _i = ({ (arch) = seccomp_local_archs[0]; 0; });   \
             (arch) != SECCOMP_LOCAL_ARCH_END;                          \
             (arch) = seccomp_local_archs[++_i])                        \
                if ((arch) != SECCOMP_LOCAL_ARCH_BLOCKED)

/* EACCES: does not have the CAP_SYS_ADMIN or no_new_privs == 1
 * ENOMEM: out of memory, failed to allocate space for a libseccomp structure, or would exceed a defined constant
 * EFAULT: addresses passed as args (by libseccomp) are invalid */
static inline bool ERRNO_IS_NEG_SECCOMP_FATAL(intmax_t r) {
        return IN_SET(r,
                      -EPERM,
                      -EACCES,
                      -ENOMEM,
                      -EFAULT);
}
_DEFINE_ABS_WRAPPER(SECCOMP_FATAL);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(scmp_filter_ctx, seccomp_release, NULL);

int parse_syscall_archs(char **l, Set **ret_archs);

uint32_t scmp_act_kill_process(void);

int parse_syscall_and_errno(const char *in, char **name, int *error);

int seccomp_suppress_sync(void);

#else

static inline bool is_seccomp_available(void) {
        return false;
}

#endif

/* This is a special value to be used where syscall filters otherwise expect errno numbers, will be
   replaced with real seccomp action. */
enum {
        SECCOMP_ERROR_NUMBER_KILL = INT_MAX - 1,
};

static inline bool seccomp_errno_or_action_is_valid(int n) {
        return n == SECCOMP_ERROR_NUMBER_KILL || errno_is_valid(n);
}

static inline int seccomp_parse_errno_or_action(const char *p) {
        if (streq_ptr(p, "kill"))
                return SECCOMP_ERROR_NUMBER_KILL;
        return parse_errno(p);
}

static inline const char* seccomp_errno_or_action_to_string(int num) {
        if (num == SECCOMP_ERROR_NUMBER_KILL)
                return "kill";
        return errno_to_name(num);
}
