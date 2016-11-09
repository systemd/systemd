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

#include <errno.h>
#include <seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

#include "alloc-util.h"
#include "macro.h"
#include "nsflags.h"
#include "seccomp-util.h"
#include "string-util.h"
#include "util.h"

const char* seccomp_arch_to_string(uint32_t c) {
        /* Maintain order used in <seccomp.h>.
         *
         * Names used here should be the same as those used for ConditionArchitecture=,
         * except for "subarchitectures" like x32. */

        switch(c) {
        case SCMP_ARCH_NATIVE:
                return "native";
        case SCMP_ARCH_X86:
                return "x86";
        case SCMP_ARCH_X86_64:
                return "x86-64";
        case SCMP_ARCH_X32:
                return "x32";
        case SCMP_ARCH_ARM:
                return "arm";
        case SCMP_ARCH_AARCH64:
                return "arm64";
        case SCMP_ARCH_MIPS:
                return "mips";
        case SCMP_ARCH_MIPS64:
                return "mips64";
        case SCMP_ARCH_MIPS64N32:
                return "mips64-n32";
        case SCMP_ARCH_MIPSEL:
                return "mips-le";
        case SCMP_ARCH_MIPSEL64:
                return "mips64-le";
        case SCMP_ARCH_MIPSEL64N32:
                return "mips64-le-n32";
        case SCMP_ARCH_PPC:
                return "ppc";
        case SCMP_ARCH_PPC64:
                return "ppc64";
        case SCMP_ARCH_PPC64LE:
                return "ppc64-le";
        case SCMP_ARCH_S390:
                return "s390";
        case SCMP_ARCH_S390X:
                return "s390x";
        default:
                return NULL;
        }
}

int seccomp_arch_from_string(const char *n, uint32_t *ret) {
        if (!n)
                return -EINVAL;

        assert(ret);

        if (streq(n, "native"))
                *ret = SCMP_ARCH_NATIVE;
        else if (streq(n, "x86"))
                *ret = SCMP_ARCH_X86;
        else if (streq(n, "x86-64"))
                *ret = SCMP_ARCH_X86_64;
        else if (streq(n, "x32"))
                *ret = SCMP_ARCH_X32;
        else if (streq(n, "arm"))
                *ret = SCMP_ARCH_ARM;
        else if (streq(n, "arm64"))
                *ret = SCMP_ARCH_AARCH64;
        else if (streq(n, "mips"))
                *ret = SCMP_ARCH_MIPS;
        else if (streq(n, "mips64"))
                *ret = SCMP_ARCH_MIPS64;
        else if (streq(n, "mips64-n32"))
                *ret = SCMP_ARCH_MIPS64N32;
        else if (streq(n, "mips-le"))
                *ret = SCMP_ARCH_MIPSEL;
        else if (streq(n, "mips64-le"))
                *ret = SCMP_ARCH_MIPSEL64;
        else if (streq(n, "mips64-le-n32"))
                *ret = SCMP_ARCH_MIPSEL64N32;
        else if (streq(n, "ppc"))
                *ret = SCMP_ARCH_PPC;
        else if (streq(n, "ppc64"))
                *ret = SCMP_ARCH_PPC64;
        else if (streq(n, "ppc64-le"))
                *ret = SCMP_ARCH_PPC64LE;
        else if (streq(n, "s390"))
                *ret = SCMP_ARCH_S390;
        else if (streq(n, "s390x"))
                *ret = SCMP_ARCH_S390X;
        else
                return -EINVAL;

        return 0;
}

int seccomp_init_conservative(scmp_filter_ctx *ret, uint32_t default_action) {
        scmp_filter_ctx seccomp;
        int r;

        /* Much like seccomp_init(), but tries to be a bit more conservative in its defaults: all secondary archs are
         * added by default, and NNP is turned off. */

        seccomp = seccomp_init(default_action);
        if (!seccomp)
                return -ENOMEM;

        r = seccomp_add_secondary_archs(seccomp);
        if (r < 0)
                goto finish;

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
        if (r < 0)
                goto finish;

        *ret = seccomp;
        return 0;

finish:
        seccomp_release(seccomp);
        return r;
}

int seccomp_add_secondary_archs(scmp_filter_ctx ctx) {

        /* Add in all possible secondary archs we are aware of that
         * this kernel might support. */

        static const int seccomp_arches[] = {
#if defined(__i386__) || defined(__x86_64__)
                SCMP_ARCH_X86,
                SCMP_ARCH_X86_64,
                SCMP_ARCH_X32,

#elif defined(__arm__) || defined(__aarch64__)
                SCMP_ARCH_ARM,
                SCMP_ARCH_AARCH64,

#elif defined(__arm__) || defined(__aarch64__)
                SCMP_ARCH_ARM,
                SCMP_ARCH_AARCH64,

#elif defined(__mips__) || defined(__mips64__)
                SCMP_ARCH_MIPS,
                SCMP_ARCH_MIPS64,
                SCMP_ARCH_MIPS64N32,
                SCMP_ARCH_MIPSEL,
                SCMP_ARCH_MIPSEL64,
                SCMP_ARCH_MIPSEL64N32,

#elif defined(__powerpc__) || defined(__powerpc64__)
                SCMP_ARCH_PPC,
                SCMP_ARCH_PPC64,
                SCMP_ARCH_PPC64LE,

#elif defined(__s390__) || defined(__s390x__)
                SCMP_ARCH_S390,
                SCMP_ARCH_S390X,
#endif
        };

        unsigned i;
        int r;

        for (i = 0; i < ELEMENTSOF(seccomp_arches); i++) {
                r = seccomp_arch_add(ctx, seccomp_arches[i]);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        return 0;
}

static bool is_basic_seccomp_available(void) {
        int r;
        r = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
        return r >= 0;
}

static bool is_seccomp_filter_available(void) {
        int r;
        r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL, 0, 0);
        return r < 0 && errno == EFAULT;
}

bool is_seccomp_available(void) {
        static int cached_enabled = -1;
        if (cached_enabled < 0)
                cached_enabled = is_basic_seccomp_available() && is_seccomp_filter_available();
        return cached_enabled;
}

const SyscallFilterSet syscall_filter_sets[_SYSCALL_FILTER_SET_MAX] = {
        [SYSCALL_FILTER_SET_DEFAULT] = {
                .name = "@default",
                .help = "System calls that are always permitted",
                .value =
                "clock_getres\0"
                "clock_gettime\0"
                "clock_nanosleep\0"
                "execve\0"
                "exit\0"
                "exit_group\0"
                "getrlimit\0"      /* make sure processes can query stack size and such */
                "gettimeofday\0"
                "nanosleep\0"
                "pause\0"
                "rt_sigreturn\0"
                "sigreturn\0"
                "time\0"
        },
        [SYSCALL_FILTER_SET_BASIC_IO] = {
                .name = "@basic-io",
                .help = "Basic IO",
                .value =
                "close\0"
                "dup2\0"
                "dup3\0"
                "dup\0"
                "lseek\0"
                "pread64\0"
                "preadv\0"
                "pwrite64\0"
                "pwritev\0"
                "read\0"
                "readv\0"
                "write\0"
                "writev\0"
        },
        [SYSCALL_FILTER_SET_CLOCK] = {
                .name = "@clock",
                .help = "Change the system time",
                .value =
                "adjtimex\0"
                "clock_adjtime\0"
                "clock_settime\0"
                "settimeofday\0"
                "stime\0"
        },
        [SYSCALL_FILTER_SET_CPU_EMULATION] = {
                .name = "@cpu-emulation",
                .help = "System calls for CPU emulation functionality",
                .value =
                "modify_ldt\0"
                "subpage_prot\0"
                "switch_endian\0"
                "vm86\0"
                "vm86old\0"
        },
        [SYSCALL_FILTER_SET_DEBUG] = {
                .name = "@debug",
                .help = "Debugging, performance monitoring and tracing functionality",
                .value =
                "lookup_dcookie\0"
                "perf_event_open\0"
                "process_vm_readv\0"
                "process_vm_writev\0"
                "ptrace\0"
                "rtas\0"
#ifdef __NR_s390_runtime_instr
                "s390_runtime_instr\0"
#endif
                "sys_debug_setcontext\0"
        },
        [SYSCALL_FILTER_SET_IO_EVENT] = {
                .name = "@io-event",
                .help = "Event loop system calls",
                .value =
                "_newselect\0"
                "epoll_create1\0"
                "epoll_create\0"
                "epoll_ctl\0"
                "epoll_ctl_old\0"
                "epoll_pwait\0"
                "epoll_wait\0"
                "epoll_wait_old\0"
                "eventfd2\0"
                "eventfd\0"
                "poll\0"
                "ppoll\0"
                "pselect6\0"
                "select\0"
        },
        [SYSCALL_FILTER_SET_IPC] = {
                .name = "@ipc",
                .help = "SysV IPC, POSIX Message Queues or other IPC",
                .value =
                "ipc\0"
                "memfd_create\0"
                "mq_getsetattr\0"
                "mq_notify\0"
                "mq_open\0"
                "mq_timedreceive\0"
                "mq_timedsend\0"
                "mq_unlink\0"
                "msgctl\0"
                "msgget\0"
                "msgrcv\0"
                "msgsnd\0"
                "pipe2\0"
                "pipe\0"
                "process_vm_readv\0"
                "process_vm_writev\0"
                "semctl\0"
                "semget\0"
                "semop\0"
                "semtimedop\0"
                "shmat\0"
                "shmctl\0"
                "shmdt\0"
                "shmget\0"
        },
        [SYSCALL_FILTER_SET_KEYRING] = {
                .name = "@keyring",
                .help = "Kernel keyring access",
                .value =
                "add_key\0"
                "keyctl\0"
                "request_key\0"
        },
        [SYSCALL_FILTER_SET_MODULE] = {
                .name = "@module",
                .help = "Loading and unloading of kernel modules",
                .value =
                "delete_module\0"
                "finit_module\0"
                "init_module\0"
        },
        [SYSCALL_FILTER_SET_MOUNT] = {
                .name = "@mount",
                .help = "Mounting and unmounting of file systems",
                .value =
                "chroot\0"
                "mount\0"
                "pivot_root\0"
                "umount2\0"
                "umount\0"
        },
        [SYSCALL_FILTER_SET_NETWORK_IO] = {
                .name = "@network-io",
                .help = "Network or Unix socket IO, should not be needed if not network facing",
                .value =
                "accept4\0"
                "accept\0"
                "bind\0"
                "connect\0"
                "getpeername\0"
                "getsockname\0"
                "getsockopt\0"
                "listen\0"
                "recv\0"
                "recvfrom\0"
                "recvmmsg\0"
                "recvmsg\0"
                "send\0"
                "sendmmsg\0"
                "sendmsg\0"
                "sendto\0"
                "setsockopt\0"
                "shutdown\0"
                "socket\0"
                "socketcall\0"
                "socketpair\0"
        },
        [SYSCALL_FILTER_SET_OBSOLETE] = {
                /* some unknown even to libseccomp */
                .name = "@obsolete",
                .help = "Unusual, obsolete or unimplemented system calls",
                .value =
                "_sysctl\0"
                "afs_syscall\0"
                "break\0"
                "create_module\0"
                "ftime\0"
                "get_kernel_syms\0"
                "getpmsg\0"
                "gtty\0"
                "lock\0"
                "mpx\0"
                "prof\0"
                "profil\0"
                "putpmsg\0"
                "query_module\0"
                "security\0"
                "sgetmask\0"
                "ssetmask\0"
                "stty\0"
                "sysfs\0"
                "tuxcall\0"
                "ulimit\0"
                "uselib\0"
                "ustat\0"
                "vserver\0"
        },
        [SYSCALL_FILTER_SET_PRIVILEGED] = {
                .name = "@privileged",
                .help = "All system calls which need super-user capabilities",
                .value =
                "@clock\0"
                "@module\0"
                "@raw-io\0"
                "acct\0"
                "bdflush\0"
                "bpf\0"
                "capset\0"
                "chown32\0"
                "chown\0"
                "chroot\0"
                "fchown32\0"
                "fchown\0"
                "fchownat\0"
                "kexec_file_load\0"
                "kexec_load\0"
                "lchown32\0"
                "lchown\0"
                "nfsservctl\0"
                "pivot_root\0"
                "quotactl\0"
                "reboot\0"
                "setdomainname\0"
                "setfsuid32\0"
                "setfsuid\0"
                "setgroups32\0"
                "setgroups\0"
                "sethostname\0"
                "setresuid32\0"
                "setresuid\0"
                "setreuid32\0"
                "setreuid\0"
                "setuid32\0"
                "setuid\0"
                "swapoff\0"
                "swapon\0"
                "_sysctl\0"
                "vhangup\0"
        },
        [SYSCALL_FILTER_SET_PROCESS] = {
                .name = "@process",
                .help = "Process control, execution, namespaceing operations",
                .value =
                "arch_prctl\0"
                "clone\0"
                "execveat\0"
                "fork\0"
                "kill\0"
                "prctl\0"
                "setns\0"
                "tgkill\0"
                "tkill\0"
                "unshare\0"
                "vfork\0"
        },
        [SYSCALL_FILTER_SET_RAW_IO] = {
                .name = "@raw-io",
                .help = "Raw I/O port access",
                .value =
                "ioperm\0"
                "iopl\0"
                "pciconfig_iobase\0"
                "pciconfig_read\0"
                "pciconfig_write\0"
#ifdef __NR_s390_pci_mmio_read
                "s390_pci_mmio_read\0"
#endif
#ifdef __NR_s390_pci_mmio_write
                "s390_pci_mmio_write\0"
#endif
        },
        [SYSCALL_FILTER_SET_RESOURCES] = {
                /* Alter resource settings */
                .name = "@resources",
                .value =
                "sched_setparam\0"
                "sched_setscheduler\0"
                "sched_setaffinity\0"
                "setpriority\0"
                "setrlimit\0"
                "set_mempolicy\0"
                "migrate_pages\0"
                "move_pages\0"
                "mbind\0"
                "sched_setattr\0"
                "prlimit64\0"
        },
};

const SyscallFilterSet *syscall_filter_set_find(const char *name) {
        unsigned i;

        if (isempty(name) || name[0] != '@')
                return NULL;

        for (i = 0; i < _SYSCALL_FILTER_SET_MAX; i++)
                if (streq(syscall_filter_sets[i].name, name))
                        return syscall_filter_sets + i;

        return NULL;
}

int seccomp_add_syscall_filter_set(scmp_filter_ctx seccomp, const SyscallFilterSet *set, uint32_t action) {
        const char *sys;
        int r;

        assert(seccomp);
        assert(set);

        NULSTR_FOREACH(sys, set->value) {
                int id;

                if (sys[0] == '@') {
                        const SyscallFilterSet *other;

                        other = syscall_filter_set_find(sys);
                        if (!other)
                                return -EINVAL;

                        r = seccomp_add_syscall_filter_set(seccomp, other, action);
                } else {
                        id = seccomp_syscall_resolve_name(sys);
                        if (id == __NR_SCMP_ERROR)
                                return -EINVAL;

                        r = seccomp_rule_add(seccomp, action, id, 0);
                }
                if (r < 0)
                        return r;
        }

        return 0;
}

int seccomp_load_filter_set(uint32_t default_action, const SyscallFilterSet *set, uint32_t action) {
        scmp_filter_ctx seccomp;
        int r;

        assert(set);

        /* The one-stop solution: allocate a seccomp object, add a filter to it, and apply it */

        r = seccomp_init_conservative(&seccomp, default_action);
        if (r < 0)
                return r;

        r = seccomp_add_syscall_filter_set(seccomp, set, action);
        if (r < 0)
                goto finish;

        r = seccomp_load(seccomp);

finish:
        seccomp_release(seccomp);
        return r;
}

int seccomp_restrict_namespaces(unsigned long retain) {
        scmp_filter_ctx seccomp;
        unsigned i;
        int r;

        if (log_get_max_level() >= LOG_DEBUG) {
                _cleanup_free_ char *s = NULL;

                (void) namespace_flag_to_string_many(retain, &s);
                log_debug("Restricting namespace to: %s.", strna(s));
        }

        /* NOOP? */
        if ((retain & NAMESPACE_FLAGS_ALL) == NAMESPACE_FLAGS_ALL)
                return 0;

        r = seccomp_init_conservative(&seccomp, SCMP_ACT_ALLOW);
        if (r < 0)
                return r;

        if ((retain & NAMESPACE_FLAGS_ALL) == 0)
                /* If every single kind of namespace shall be prohibited, then let's block the whole setns() syscall
                 * altogether. */
                r = seccomp_rule_add(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(setns),
                                0);
        else
                /* Otherwise, block only the invocations with the appropriate flags in the loop below, but also the
                 * special invocation with a zero flags argument, right here. */
                r = seccomp_rule_add(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(setns),
                                1,
                                SCMP_A1(SCMP_CMP_EQ, 0));
        if (r < 0)
                goto finish;

        for (i = 0; namespace_flag_map[i].name; i++) {
                unsigned long f;

                f = namespace_flag_map[i].flag;
                if ((retain & f) == f) {
                        log_debug("Permitting %s.", namespace_flag_map[i].name);
                        continue;
                }

                log_debug("Blocking %s.", namespace_flag_map[i].name);

                r = seccomp_rule_add(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(unshare),
                                1,
                                SCMP_A0(SCMP_CMP_MASKED_EQ, f, f));
                if (r < 0)
                        goto finish;

                r = seccomp_rule_add(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(clone),
                                1,
                                SCMP_A0(SCMP_CMP_MASKED_EQ, f, f));
                if (r < 0)
                        goto finish;

                if ((retain & NAMESPACE_FLAGS_ALL) != 0) {
                        r = seccomp_rule_add(
                                        seccomp,
                                        SCMP_ACT_ERRNO(EPERM),
                                        SCMP_SYS(setns),
                                        1,
                                        SCMP_A1(SCMP_CMP_MASKED_EQ, f, f));
                        if (r < 0)
                                goto finish;
                }
        }

        r = seccomp_load(seccomp);

finish:
        seccomp_release(seccomp);
        return r;
}
