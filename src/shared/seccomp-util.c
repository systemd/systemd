/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include "af-list.h"
#include "alloc-util.h"
#include "env-util.h"
#include "errno-list.h"
#include "macro.h"
#include "nsflags.h"
#include "nulstr-util.h"
#include "process-util.h"
#include "seccomp-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"

/* This array will be modified at runtime as seccomp_restrict_archs is called. */
uint32_t seccomp_local_archs[] = {

        /* Note: always list the native arch we are compiled as last, so that users can deny-list seccomp(), but our own calls to it still succeed */

#if defined(__x86_64__) && defined(__ILP32__)
                SCMP_ARCH_X86,
                SCMP_ARCH_X86_64,
                SCMP_ARCH_X32,         /* native */
#elif defined(__x86_64__) && !defined(__ILP32__)
                SCMP_ARCH_X86,
                SCMP_ARCH_X32,
                SCMP_ARCH_X86_64,      /* native */
#elif defined(__i386__)
                SCMP_ARCH_X86,
#elif defined(__aarch64__)
                SCMP_ARCH_ARM,
                SCMP_ARCH_AARCH64,     /* native */
#elif defined(__arm__)
                SCMP_ARCH_ARM,
#elif defined(__mips__) && __BYTE_ORDER == __BIG_ENDIAN && _MIPS_SIM == _MIPS_SIM_ABI32
                SCMP_ARCH_MIPSEL,
                SCMP_ARCH_MIPS,        /* native */
#elif defined(__mips__) && __BYTE_ORDER == __LITTLE_ENDIAN && _MIPS_SIM == _MIPS_SIM_ABI32
                SCMP_ARCH_MIPS,
                SCMP_ARCH_MIPSEL,      /* native */
#elif defined(__mips__) && __BYTE_ORDER == __BIG_ENDIAN && _MIPS_SIM == _MIPS_SIM_ABI64
                SCMP_ARCH_MIPSEL,
                SCMP_ARCH_MIPS,
                SCMP_ARCH_MIPSEL64N32,
                SCMP_ARCH_MIPS64N32,
                SCMP_ARCH_MIPSEL64,
                SCMP_ARCH_MIPS64,      /* native */
#elif defined(__mips__) && __BYTE_ORDER == __LITTLE_ENDIAN && _MIPS_SIM == _MIPS_SIM_ABI64
                SCMP_ARCH_MIPS,
                SCMP_ARCH_MIPSEL,
                SCMP_ARCH_MIPS64N32,
                SCMP_ARCH_MIPSEL64N32,
                SCMP_ARCH_MIPS64,
                SCMP_ARCH_MIPSEL64,    /* native */
#elif defined(__mips__) && __BYTE_ORDER == __BIG_ENDIAN && _MIPS_SIM == _MIPS_SIM_NABI32
                SCMP_ARCH_MIPSEL,
                SCMP_ARCH_MIPS,
                SCMP_ARCH_MIPSEL64,
                SCMP_ARCH_MIPS64,
                SCMP_ARCH_MIPSEL64N32,
                SCMP_ARCH_MIPS64N32,   /* native */
#elif defined(__mips__) && __BYTE_ORDER == __LITTLE_ENDIAN && _MIPS_SIM == _MIPS_SIM_NABI32
                SCMP_ARCH_MIPS,
                SCMP_ARCH_MIPSEL,
                SCMP_ARCH_MIPS64,
                SCMP_ARCH_MIPSEL64,
                SCMP_ARCH_MIPS64N32,
                SCMP_ARCH_MIPSEL64N32, /* native */
#elif defined(__powerpc64__) && __BYTE_ORDER == __BIG_ENDIAN
                SCMP_ARCH_PPC,
                SCMP_ARCH_PPC64LE,
                SCMP_ARCH_PPC64,       /* native */
#elif defined(__powerpc64__) && __BYTE_ORDER == __LITTLE_ENDIAN
                SCMP_ARCH_PPC,
                SCMP_ARCH_PPC64,
                SCMP_ARCH_PPC64LE,     /* native */
#elif defined(__powerpc__)
                SCMP_ARCH_PPC,
#elif defined(__riscv) && __riscv_xlen == 64 && defined(SCMP_ARCH_RISCV64)
                SCMP_ARCH_RISCV64,
#elif defined(__s390x__)
                SCMP_ARCH_S390,
                SCMP_ARCH_S390X,      /* native */
#elif defined(__s390__)
                SCMP_ARCH_S390,
#endif
                SECCOMP_LOCAL_ARCH_END
        };

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
#ifdef SCMP_ARCH_RISCV64
        case SCMP_ARCH_RISCV64:
                return "riscv64";
#endif
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
#ifdef SCMP_ARCH_RISCV64
        else if (streq(n, "riscv64"))
                *ret = SCMP_ARCH_RISCV64;
#endif
        else if (streq(n, "s390"))
                *ret = SCMP_ARCH_S390;
        else if (streq(n, "s390x"))
                *ret = SCMP_ARCH_S390X;
        else
                return -EINVAL;

        return 0;
}

int seccomp_init_for_arch(scmp_filter_ctx *ret, uint32_t arch, uint32_t default_action) {
        _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
        int r;

        /* Much like seccomp_init(), but initializes the filter for one specific architecture only, without affecting
         * any others. Also, turns off the NNP fiddling. */

        seccomp = seccomp_init(default_action);
        if (!seccomp)
                return -ENOMEM;

        if (arch != SCMP_ARCH_NATIVE &&
            arch != seccomp_arch_native()) {

                r = seccomp_arch_remove(seccomp, seccomp_arch_native());
                if (r < 0)
                        return r;

                r = seccomp_arch_add(seccomp, arch);
                if (r < 0)
                        return r;

                assert(seccomp_arch_exist(seccomp, arch) >= 0);
                assert(seccomp_arch_exist(seccomp, SCMP_ARCH_NATIVE) == -EEXIST);
                assert(seccomp_arch_exist(seccomp, seccomp_arch_native()) == -EEXIST);
        } else {
                assert(seccomp_arch_exist(seccomp, SCMP_ARCH_NATIVE) >= 0);
                assert(seccomp_arch_exist(seccomp, seccomp_arch_native()) >= 0);
        }

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_ALLOW);
        if (r < 0)
                return r;

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
        if (r < 0)
                return r;

#if SCMP_VER_MAJOR >= 3 || (SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR >= 4)
        if (getenv_bool("SYSTEMD_LOG_SECCOMP") > 0) {
                r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_LOG, 1);
                if (r < 0)
                        log_debug_errno(r, "Failed to enable seccomp event logging: %m");
        }
#endif

        *ret = TAKE_PTR(seccomp);
        return 0;
}

static bool is_basic_seccomp_available(void) {
        return prctl(PR_GET_SECCOMP, 0, 0, 0, 0) >= 0;
}

static bool is_seccomp_filter_available(void) {
        return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL, 0, 0) < 0 &&
                errno == EFAULT;
}

bool is_seccomp_available(void) {
        static int cached_enabled = -1;

        if (cached_enabled < 0) {
                int b;

                b = getenv_bool_secure("SYSTEMD_SECCOMP");
                if (b != 0) {
                        if (b < 0 && b != -ENXIO) /* ENXIO: env var unset */
                                log_debug_errno(b, "Failed to parse $SYSTEMD_SECCOMP value, ignoring.");

                        cached_enabled =
                                is_basic_seccomp_available() &&
                                is_seccomp_filter_available();
                } else
                        cached_enabled = false;
        }

        return cached_enabled;
}

const SyscallFilterSet syscall_filter_sets[_SYSCALL_FILTER_SET_MAX] = {
        [SYSCALL_FILTER_SET_DEFAULT] = {
                .name = "@default",
                .help = "System calls that are always permitted",
                .value =
                "arch_prctl\0"      /* Used during platform-specific initialization by ld-linux.so. */
                "brk\0"
                "cacheflush\0"
                "clock_getres\0"
                "clock_getres_time64\0"
                "clock_gettime\0"
                "clock_gettime64\0"
                "clock_nanosleep\0"
                "clock_nanosleep_time64\0"
                "execve\0"
                "exit\0"
                "exit_group\0"
                "futex\0"
                "futex_time64\0"
                "get_robust_list\0"
                "get_thread_area\0"
                "getegid\0"
                "getegid32\0"
                "geteuid\0"
                "geteuid32\0"
                "getgid\0"
                "getgid32\0"
                "getgroups\0"
                "getgroups32\0"
                "getpgid\0"
                "getpgrp\0"
                "getpid\0"
                "getppid\0"
                "getrandom\0"
                "getresgid\0"
                "getresgid32\0"
                "getresuid\0"
                "getresuid32\0"
                "getrlimit\0"      /* make sure processes can query stack size and such */
                "getsid\0"
                "gettid\0"
                "gettimeofday\0"
                "getuid\0"
                "getuid32\0"
                "membarrier\0"
                "mmap\0"
                "mmap2\0"
                "mprotect\0"
                "munmap\0"
                "nanosleep\0"
                "pause\0"
                "prlimit64\0"
                "restart_syscall\0"
                "rseq\0"
                "rt_sigreturn\0"
                "sched_getaffinity\0"
                "sched_yield\0"
                "set_robust_list\0"
                "set_thread_area\0"
                "set_tid_address\0"
                "set_tls\0"
                "sigreturn\0"
                "time\0"
                "ugetrlimit\0"
        },
        [SYSCALL_FILTER_SET_AIO] = {
                .name = "@aio",
                .help = "Asynchronous IO",
                .value =
                "io_cancel\0"
                "io_destroy\0"
                "io_getevents\0"
                "io_pgetevents\0"
                "io_pgetevents_time64\0"
                "io_setup\0"
                "io_submit\0"
                "io_uring_enter\0"
                "io_uring_register\0"
                "io_uring_setup\0"
        },
        [SYSCALL_FILTER_SET_BASIC_IO] = {
                .name = "@basic-io",
                .help = "Basic IO",
                .value =
                "_llseek\0"
                "close\0"
                "close_range\0"
                "dup\0"
                "dup2\0"
                "dup3\0"
                "lseek\0"
                "pread64\0"
                "preadv\0"
                "preadv2\0"
                "pwrite64\0"
                "pwritev\0"
                "pwritev2\0"
                "read\0"
                "readv\0"
                "write\0"
                "writev\0"
        },
        [SYSCALL_FILTER_SET_CHOWN] = {
                .name = "@chown",
                .help = "Change ownership of files and directories",
                .value =
                "chown\0"
                "chown32\0"
                "fchown\0"
                "fchown32\0"
                "fchownat\0"
                "lchown\0"
                "lchown32\0"
        },
        [SYSCALL_FILTER_SET_CLOCK] = {
                .name = "@clock",
                .help = "Change the system time",
                .value =
                "adjtimex\0"
                "clock_adjtime\0"
                "clock_adjtime64\0"
                "clock_settime\0"
                "clock_settime64\0"
                "settimeofday\0"
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
                "pidfd_getfd\0"
                "ptrace\0"
                "rtas\0"
#if defined __s390__ || defined __s390x__
                "s390_runtime_instr\0"
#endif
                "sys_debug_setcontext\0"
        },
        [SYSCALL_FILTER_SET_FILE_SYSTEM] = {
                .name = "@file-system",
                .help = "File system operations",
                .value =
                "access\0"
                "chdir\0"
                "chmod\0"
                "close\0"
                "creat\0"
                "faccessat\0"
                "faccessat2\0"
                "fallocate\0"
                "fchdir\0"
                "fchmod\0"
                "fchmodat\0"
                "fcntl\0"
                "fcntl64\0"
                "fgetxattr\0"
                "flistxattr\0"
                "fremovexattr\0"
                "fsetxattr\0"
                "fstat\0"
                "fstat64\0"
                "fstatat64\0"
                "fstatfs\0"
                "fstatfs64\0"
                "ftruncate\0"
                "ftruncate64\0"
                "futimesat\0"
                "getcwd\0"
                "getdents\0"
                "getdents64\0"
                "getxattr\0"
                "inotify_add_watch\0"
                "inotify_init\0"
                "inotify_init1\0"
                "inotify_rm_watch\0"
                "lgetxattr\0"
                "link\0"
                "linkat\0"
                "listxattr\0"
                "llistxattr\0"
                "lremovexattr\0"
                "lsetxattr\0"
                "lstat\0"
                "lstat64\0"
                "mkdir\0"
                "mkdirat\0"
                "mknod\0"
                "mknodat\0"
                "newfstatat\0"
                "oldfstat\0"
                "oldlstat\0"
                "oldstat\0"
                "open\0"
                "openat\0"
                "openat2\0"
                "readlink\0"
                "readlinkat\0"
                "removexattr\0"
                "rename\0"
                "renameat\0"
                "renameat2\0"
                "rmdir\0"
                "setxattr\0"
                "stat\0"
                "stat64\0"
                "statfs\0"
                "statfs64\0"
                "statx\0"
                "symlink\0"
                "symlinkat\0"
                "truncate\0"
                "truncate64\0"
                "unlink\0"
                "unlinkat\0"
                "utime\0"
                "utimensat\0"
                "utimensat_time64\0"
                "utimes\0"
        },
        [SYSCALL_FILTER_SET_IO_EVENT] = {
                .name = "@io-event",
                .help = "Event loop system calls",
                .value =
                "_newselect\0"
                "epoll_create\0"
                "epoll_create1\0"
                "epoll_ctl\0"
                "epoll_ctl_old\0"
                "epoll_pwait\0"
                "epoll_pwait2\0"
                "epoll_wait\0"
                "epoll_wait_old\0"
                "eventfd\0"
                "eventfd2\0"
                "poll\0"
                "ppoll\0"
                "ppoll_time64\0"
                "pselect6\0"
                "pselect6_time64\0"
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
                "mq_timedreceive_time64\0"
                "mq_timedsend\0"
                "mq_timedsend_time64\0"
                "mq_unlink\0"
                "msgctl\0"
                "msgget\0"
                "msgrcv\0"
                "msgsnd\0"
                "pipe\0"
                "pipe2\0"
                "process_madvise\0"
                "process_vm_readv\0"
                "process_vm_writev\0"
                "semctl\0"
                "semget\0"
                "semop\0"
                "semtimedop\0"
                "semtimedop_time64\0"
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
        [SYSCALL_FILTER_SET_MEMLOCK] = {
                .name = "@memlock",
                .help = "Memory locking control",
                .value =
                "mlock\0"
                "mlock2\0"
                "mlockall\0"
                "munlock\0"
                "munlockall\0"
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
                "fsconfig\0"
                "fsmount\0"
                "fsopen\0"
                "fspick\0"
                "mount\0"
                "mount_setattr\0"
                "move_mount\0"
                "open_tree\0"
                "pivot_root\0"
                "umount\0"
                "umount2\0"
        },
        [SYSCALL_FILTER_SET_NETWORK_IO] = {
                .name = "@network-io",
                .help = "Network or Unix socket IO, should not be needed if not network facing",
                .value =
                "accept\0"
                "accept4\0"
                "bind\0"
                "connect\0"
                "getpeername\0"
                "getsockname\0"
                "getsockopt\0"
                "listen\0"
                "recv\0"
                "recvfrom\0"
                "recvmmsg\0"
                "recvmmsg_time64\0"
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
                "bdflush\0"
                "break\0"
                "create_module\0"
                "ftime\0"
                "get_kernel_syms\0"
                "getpmsg\0"
                "gtty\0"
                "idle\0"
                "lock\0"
                "mpx\0"
                "prof\0"
                "profil\0"
                "putpmsg\0"
                "query_module\0"
                "security\0"
                "sgetmask\0"
                "ssetmask\0"
                "stime\0"
                "stty\0"
                "sysfs\0"
                "tuxcall\0"
                "ulimit\0"
                "uselib\0"
                "ustat\0"
                "vserver\0"
        },
        [SYSCALL_FILTER_SET_PKEY] = {
                .name = "@pkey",
                .help = "System calls used for memory protection keys",
                .value =
                "pkey_alloc\0"
                "pkey_free\0"
                "pkey_mprotect\0"
        },
        [SYSCALL_FILTER_SET_PRIVILEGED] = {
                .name = "@privileged",
                .help = "All system calls which need super-user capabilities",
                .value =
                "@chown\0"
                "@clock\0"
                "@module\0"
                "@raw-io\0"
                "@reboot\0"
                "@swap\0"
                "_sysctl\0"
                "acct\0"
                "bpf\0"
                "capset\0"
                "chroot\0"
                "fanotify_init\0"
                "fanotify_mark\0"
                "nfsservctl\0"
                "open_by_handle_at\0"
                "pivot_root\0"
                "quotactl\0"
                "setdomainname\0"
                "setfsuid\0"
                "setfsuid32\0"
                "setgroups\0"
                "setgroups32\0"
                "sethostname\0"
                "setresuid\0"
                "setresuid32\0"
                "setreuid\0"
                "setreuid32\0"
                "setuid\0"      /* We list the explicit system calls here, as @setuid also includes setgid() which is not necessarily privileged */
                "setuid32\0"
                "vhangup\0"
        },
        [SYSCALL_FILTER_SET_PROCESS] = {
                .name = "@process",
                .help = "Process control, execution, namespacing operations",
                .value =
                "capget\0"      /* Able to query arbitrary processes */
                "clone\0"
                "clone3\0"
                "execveat\0"
                "fork\0"
                "getrusage\0"
                "kill\0"
                "pidfd_open\0"
                "pidfd_send_signal\0"
                "prctl\0"
                "rt_sigqueueinfo\0"
                "rt_tgsigqueueinfo\0"
                "setns\0"
                "swapcontext\0" /* Some archs e.g. powerpc32 are using it to do userspace context switches */
                "tgkill\0"
                "times\0"
                "tkill\0"
                "unshare\0"
                "vfork\0"
                "wait4\0"
                "waitid\0"
                "waitpid\0"
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
#if defined __s390__ || defined __s390x__
                "s390_pci_mmio_read\0"
                "s390_pci_mmio_write\0"
#endif
        },
        [SYSCALL_FILTER_SET_REBOOT] = {
                .name = "@reboot",
                .help = "Reboot and reboot preparation/kexec",
                .value =
                "kexec_file_load\0"
                "kexec_load\0"
                "reboot\0"
        },
        [SYSCALL_FILTER_SET_RESOURCES] = {
                .name = "@resources",
                .help = "Alter resource settings",
                .value =
                "ioprio_set\0"
                "mbind\0"
                "migrate_pages\0"
                "move_pages\0"
                "nice\0"
                "sched_setaffinity\0"
                "sched_setattr\0"
                "sched_setparam\0"
                "sched_setscheduler\0"
                "set_mempolicy\0"
                "setpriority\0"
                "setrlimit\0"
        },
        [SYSCALL_FILTER_SET_SETUID] = {
                .name = "@setuid",
                .help = "Operations for changing user/group credentials",
                .value =
                "setgid\0"
                "setgid32\0"
                "setgroups\0"
                "setgroups32\0"
                "setregid\0"
                "setregid32\0"
                "setresgid\0"
                "setresgid32\0"
                "setresuid\0"
                "setresuid32\0"
                "setreuid\0"
                "setreuid32\0"
                "setuid\0"
                "setuid32\0"
        },
        [SYSCALL_FILTER_SET_SIGNAL] = {
                .name = "@signal",
                .help = "Process signal handling",
                .value =
                "rt_sigaction\0"
                "rt_sigpending\0"
                "rt_sigprocmask\0"
                "rt_sigsuspend\0"
                "rt_sigtimedwait\0"
                "rt_sigtimedwait_time64\0"
                "sigaction\0"
                "sigaltstack\0"
                "signal\0"
                "signalfd\0"
                "signalfd4\0"
                "sigpending\0"
                "sigprocmask\0"
                "sigsuspend\0"
        },
        [SYSCALL_FILTER_SET_SWAP] = {
                .name = "@swap",
                .help = "Enable/disable swap devices",
                .value =
                "swapoff\0"
                "swapon\0"
        },
        [SYSCALL_FILTER_SET_SYNC] = {
                .name = "@sync",
                .help = "Synchronize files and memory to storage",
                .value =
                "fdatasync\0"
                "fsync\0"
                "msync\0"
                "sync\0"
                "sync_file_range\0"
                "sync_file_range2\0"
                "syncfs\0"
        },
        [SYSCALL_FILTER_SET_SYSTEM_SERVICE] = {
                .name = "@system-service",
                .help = "General system service operations",
                .value =
                "@aio\0"
                "@basic-io\0"
                "@chown\0"
                "@default\0"
                "@file-system\0"
                "@io-event\0"
                "@ipc\0"
                "@keyring\0"
                "@memlock\0"
                "@network-io\0"
                "@process\0"
                "@resources\0"
                "@setuid\0"
                "@signal\0"
                "@sync\0"
                "@timer\0"
                "capget\0"
                "capset\0"
                "copy_file_range\0"
                "fadvise64\0"
                "fadvise64_64\0"
                "flock\0"
                "get_mempolicy\0"
                "getcpu\0"
                "getpriority\0"
                "ioctl\0"
                "ioprio_get\0"
                "kcmp\0"
                "madvise\0"
                "mremap\0"
                "name_to_handle_at\0"
                "oldolduname\0"
                "olduname\0"
                "personality\0"
                "readahead\0"
                "readdir\0"
                "remap_file_pages\0"
                "sched_get_priority_max\0"
                "sched_get_priority_min\0"
                "sched_getattr\0"
                "sched_getparam\0"
                "sched_getscheduler\0"
                "sched_rr_get_interval\0"
                "sched_rr_get_interval_time64\0"
                "sched_yield\0"
                "sendfile\0"
                "sendfile64\0"
                "setfsgid\0"
                "setfsgid32\0"
                "setfsuid\0"
                "setfsuid32\0"
                "setpgid\0"
                "setsid\0"
                "splice\0"
                "sysinfo\0"
                "tee\0"
                "umask\0"
                "uname\0"
                "userfaultfd\0"
                "vmsplice\0"
        },
        [SYSCALL_FILTER_SET_TIMER] = {
                .name = "@timer",
                .help = "Schedule operations by time",
                .value =
                "alarm\0"
                "getitimer\0"
                "setitimer\0"
                "timer_create\0"
                "timer_delete\0"
                "timer_getoverrun\0"
                "timer_gettime\0"
                "timer_gettime64\0"
                "timer_settime\0"
                "timer_settime64\0"
                "timerfd_create\0"
                "timerfd_gettime\0"
                "timerfd_gettime64\0"
                "timerfd_settime\0"
                "timerfd_settime64\0"
                "times\0"
        },
        [SYSCALL_FILTER_SET_KNOWN] = {
                .name = "@known",
                .help = "All known syscalls declared in the kernel",
                .value =
#include "syscall-list.h"
        },
};

const SyscallFilterSet *syscall_filter_set_find(const char *name) {
        if (isempty(name) || name[0] != '@')
                return NULL;

        for (unsigned i = 0; i < _SYSCALL_FILTER_SET_MAX; i++)
                if (streq(syscall_filter_sets[i].name, name))
                        return syscall_filter_sets + i;

        return NULL;
}

static int add_syscall_filter_set(
                scmp_filter_ctx seccomp,
                const SyscallFilterSet *set,
                uint32_t action,
                char **exclude,
                bool log_missing,
                char ***added);

int seccomp_add_syscall_filter_item(
                scmp_filter_ctx *seccomp,
                const char *name,
                uint32_t action,
                char **exclude,
                bool log_missing,
                char ***added) {

        assert(seccomp);
        assert(name);

        if (strv_contains(exclude, name))
                return 0;

        /* Any syscalls that are handled are added to the *added strv. The pointer
         * must be either NULL or point to a valid pre-initialized possibly-empty strv. */

        if (name[0] == '@') {
                const SyscallFilterSet *other;

                other = syscall_filter_set_find(name);
                if (!other)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Filter set %s is not known!",
                                               name);

                return add_syscall_filter_set(seccomp, other, action, exclude, log_missing, added);

        } else {
                int id, r;

                id = seccomp_syscall_resolve_name(name);
                if (id == __NR_SCMP_ERROR) {
                        if (log_missing)
                                log_debug("System call %s is not known, ignoring.", name);
                        return 0;
                }

                r = seccomp_rule_add_exact(seccomp, action, id, 0);
                if (r < 0) {
                        /* If the system call is not known on this architecture, then that's fine, let's ignore it */
                        bool ignore = r == -EDOM;

                        if (!ignore || log_missing)
                                log_debug_errno(r, "Failed to add rule for system call %s() / %d%s: %m",
                                                name, id, ignore ? ", ignoring" : "");
                        if (!ignore)
                                return r;
                }

                if (added) {
                        r = strv_extend(added, name);
                        if (r < 0)
                                return r;
                }

                return 0;
        }
}

static int add_syscall_filter_set(
                scmp_filter_ctx seccomp,
                const SyscallFilterSet *set,
                uint32_t action,
                char **exclude,
                bool log_missing,
                char ***added) {

        const char *sys;
        int r;

        /* Any syscalls that are handled are added to the *added strv. It needs to be initialized. */

        assert(seccomp);
        assert(set);

        NULSTR_FOREACH(sys, set->value) {
                r = seccomp_add_syscall_filter_item(seccomp, sys, action, exclude, log_missing, added);
                if (r < 0)
                        return r;
        }

        return 0;
}

int seccomp_load_syscall_filter_set(uint32_t default_action, const SyscallFilterSet *set, uint32_t action, bool log_missing) {
        uint32_t arch;
        int r;

        assert(set);

        /* The one-stop solution: allocate a seccomp object, add the specified filter to it, and apply it. Once for
         * each local arch. */

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                r = seccomp_init_for_arch(&seccomp, arch, default_action);
                if (r < 0)
                        return r;

                r = add_syscall_filter_set(seccomp, set, action, NULL, log_missing, NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add filter set: %m");

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to install filter set for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

int seccomp_load_syscall_filter_set_raw(uint32_t default_action, Hashmap* filter, uint32_t action, bool log_missing) {
        uint32_t arch;
        int r;

        /* Similar to seccomp_load_syscall_filter_set(), but takes a raw Hashmap* of syscalls, instead
         * of a SyscallFilterSet* table. */

        if (hashmap_isempty(filter) && default_action == SCMP_ACT_ALLOW)
                return 0;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
                void *syscall_id, *val;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                r = seccomp_init_for_arch(&seccomp, arch, default_action);
                if (r < 0)
                        return r;

                HASHMAP_FOREACH_KEY(val, syscall_id, filter) {
                        uint32_t a = action;
                        int id = PTR_TO_INT(syscall_id) - 1;
                        int error = PTR_TO_INT(val);

                        if (error == SECCOMP_ERROR_NUMBER_KILL)
                                a = scmp_act_kill_process();
#ifdef SCMP_ACT_LOG
                        else if (action == SCMP_ACT_LOG)
                                a = SCMP_ACT_LOG;
#endif
                        else if (error >= 0)
                                a = SCMP_ACT_ERRNO(error);

                        r = seccomp_rule_add_exact(seccomp, a, id, 0);
                        if (r < 0) {
                                /* If the system call is not known on this architecture, then that's
                                 * fine, let's ignore it */
                                _cleanup_free_ char *n = NULL;
                                bool ignore;

                                n = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, id);
                                ignore = r == -EDOM;
                                if (!ignore || log_missing)
                                        log_debug_errno(r, "Failed to add rule for system call %s() / %d%s: %m",
                                                        strna(n), id, ignore ? ", ignoring" : "");
                                if (!ignore)
                                        return r;
                        }
                }

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to install systemc call filter for architecture %s, skipping: %m",
                                        seccomp_arch_to_string(arch));
        }

        return 0;
}

int seccomp_parse_syscall_filter(
                const char *name,
                int errno_num,
                Hashmap *filter,
                SeccompParseFlags flags,
                const char *unit,
                const char *filename,
                unsigned line) {

        int r;

        assert(name);
        assert(filter);

        if (!FLAGS_SET(flags, SECCOMP_PARSE_INVERT) && errno_num >= 0)
                return -EINVAL;

        if (name[0] == '@') {
                const SyscallFilterSet *set;
                const char *i;

                set = syscall_filter_set_find(name);
                if (!set) {
                        if (!FLAGS_SET(flags, SECCOMP_PARSE_PERMISSIVE))
                                return -EINVAL;

                        log_syntax(unit, FLAGS_SET(flags, SECCOMP_PARSE_LOG) ? LOG_WARNING : LOG_DEBUG, filename, line, 0,
                                   "Unknown system call group, ignoring: %s", name);
                        return 0;
                }

                NULSTR_FOREACH(i, set->value) {
                        /* Call ourselves again, for the group to parse. Note that we downgrade logging here (i.e. take
                         * away the SECCOMP_PARSE_LOG flag) since any issues in the group table are our own problem,
                         * not a problem in user configuration data and we shouldn't pretend otherwise by complaining
                         * about them. */
                        r = seccomp_parse_syscall_filter(i, errno_num, filter, flags &~ SECCOMP_PARSE_LOG, unit, filename, line);
                        if (r < 0)
                                return r;
                }
        } else {
                int id;

                id = seccomp_syscall_resolve_name(name);
                if (id == __NR_SCMP_ERROR) {
                        if (!FLAGS_SET(flags, SECCOMP_PARSE_PERMISSIVE))
                                return -EINVAL;

                        log_syntax(unit, FLAGS_SET(flags, SECCOMP_PARSE_LOG) ? LOG_WARNING : LOG_DEBUG, filename, line, 0,
                                   "Failed to parse system call, ignoring: %s", name);
                        return 0;
                }

                /* If we previously wanted to forbid a syscall and now we want to allow it, then remove
                 * it from the list. The entries in allow-list with non-negative error value will be
                 * handled with SCMP_ACT_ERRNO() instead of the default action. */
                if (!FLAGS_SET(flags, SECCOMP_PARSE_INVERT) == FLAGS_SET(flags, SECCOMP_PARSE_ALLOW_LIST) ||
                    (FLAGS_SET(flags, SECCOMP_PARSE_INVERT | SECCOMP_PARSE_ALLOW_LIST) && errno_num >= 0)) {
                        r = hashmap_put(filter, INT_TO_PTR(id + 1), INT_TO_PTR(errno_num));
                        if (r < 0)
                                switch (r) {
                                case -ENOMEM:
                                        return FLAGS_SET(flags, SECCOMP_PARSE_LOG) ? log_oom() : -ENOMEM;
                                case -EEXIST:
                                        assert_se(hashmap_update(filter, INT_TO_PTR(id + 1), INT_TO_PTR(errno_num)) == 0);
                                        break;
                                default:
                                        return r;
                                }
                } else
                        (void) hashmap_remove(filter, INT_TO_PTR(id + 1));
        }

        return 0;
}

int seccomp_restrict_namespaces(unsigned long retain) {
        uint32_t arch;
        int r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *s = NULL;

                (void) namespace_flags_to_string(retain, &s);
                log_debug("Restricting namespace to: %s.", strna(s));
        }

        /* NOOP? */
        if (FLAGS_SET(retain, NAMESPACE_FLAGS_ALL))
                return 0;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return r;

                /* We cannot filter on individual flags to clone3(), and we need to disable the
                 * syscall altogether. ENOSYS is used instead of EPERM, so that glibc and other
                 * users shall fall back to clone(), as if on an older kernel.
                 *
                 * C.f. https://github.com/flatpak/flatpak/commit/a10f52a7565c549612c92b8e736a6698a53db330,
                 * https://github.com/moby/moby/issues/42680. */

                r = seccomp_rule_add_exact(
                                seccomp,
                                SCMP_ACT_ERRNO(ENOSYS),
                                SCMP_SYS(clone3),
                                0);
                if (r < 0)
                        log_debug_errno(r, "Failed to add clone3() rule for architecture %s, ignoring: %m", seccomp_arch_to_string(arch));

                if ((retain & NAMESPACE_FLAGS_ALL) == 0)
                        /* If every single kind of namespace shall be prohibited, then let's block the whole setns() syscall
                         * altogether. */
                        r = seccomp_rule_add_exact(
                                        seccomp,
                                        SCMP_ACT_ERRNO(EPERM),
                                        SCMP_SYS(setns),
                                        0);
                else
                        /* Otherwise, block only the invocations with the appropriate flags in the loop below, but also the
                         * special invocation with a zero flags argument, right here. */
                        r = seccomp_rule_add_exact(
                                        seccomp,
                                        SCMP_ACT_ERRNO(EPERM),
                                        SCMP_SYS(setns),
                                        1,
                                        SCMP_A1(SCMP_CMP_EQ, 0));
                if (r < 0) {
                        log_debug_errno(r, "Failed to add setns() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                        continue;
                }

                for (unsigned i = 0; namespace_flag_map[i].name; i++) {
                        unsigned long f;

                        f = namespace_flag_map[i].flag;
                        if (FLAGS_SET(retain, f)) {
                                log_debug("Permitting %s.", namespace_flag_map[i].name);
                                continue;
                        }

                        log_debug("Blocking %s.", namespace_flag_map[i].name);

                        r = seccomp_rule_add_exact(
                                        seccomp,
                                        SCMP_ACT_ERRNO(EPERM),
                                        SCMP_SYS(unshare),
                                        1,
                                        SCMP_A0(SCMP_CMP_MASKED_EQ, f, f));
                        if (r < 0) {
                                log_debug_errno(r, "Failed to add unshare() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                                break;
                        }

                        /* On s390/s390x the first two parameters to clone are switched */
                        if (!IN_SET(arch, SCMP_ARCH_S390, SCMP_ARCH_S390X))
                                r = seccomp_rule_add_exact(
                                                seccomp,
                                                SCMP_ACT_ERRNO(EPERM),
                                                SCMP_SYS(clone),
                                                1,
                                                SCMP_A0(SCMP_CMP_MASKED_EQ, f, f));
                        else
                                r = seccomp_rule_add_exact(
                                                seccomp,
                                                SCMP_ACT_ERRNO(EPERM),
                                                SCMP_SYS(clone),
                                                1,
                                                SCMP_A1(SCMP_CMP_MASKED_EQ, f, f));
                        if (r < 0) {
                                log_debug_errno(r, "Failed to add clone() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                                break;
                        }

                        if ((retain & NAMESPACE_FLAGS_ALL) != 0) {
                                r = seccomp_rule_add_exact(
                                                seccomp,
                                                SCMP_ACT_ERRNO(EPERM),
                                                SCMP_SYS(setns),
                                                1,
                                                SCMP_A1(SCMP_CMP_MASKED_EQ, f, f));
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to add setns() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                                        break;
                                }
                        }
                }
                if (r < 0)
                        continue;

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to install namespace restriction rules for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

int seccomp_protect_sysctl(void) {
        uint32_t arch;
        int r;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                if (IN_SET(arch,
                           SCMP_ARCH_AARCH64,
#ifdef SCMP_ARCH_RISCV64
                           SCMP_ARCH_RISCV64,
#endif
                           SCMP_ARCH_X32
                          ))
                        /* No _sysctl syscall */
                        continue;

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return r;

                r = seccomp_rule_add_exact(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(_sysctl),
                                0);
                if (r < 0) {
                        log_debug_errno(r, "Failed to add _sysctl() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                        continue;
                }

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to install sysctl protection rules for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

int seccomp_protect_syslog(void) {
        uint32_t arch;
        int r;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return r;

                r = seccomp_rule_add_exact(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(syslog),
                                0);

                if (r < 0) {
                        log_debug_errno(r, "Failed to add syslog() rule for architecture %s, skipping %m", seccomp_arch_to_string(arch));
                        continue;
                }

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to install syslog protection rules for architecture %s, skipping %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

int seccomp_restrict_address_families(Set *address_families, bool allow_list) {
        uint32_t arch;
        int r;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
                bool supported;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                switch (arch) {

                case SCMP_ARCH_X86_64:
                case SCMP_ARCH_X32:
                case SCMP_ARCH_ARM:
                case SCMP_ARCH_AARCH64:
                case SCMP_ARCH_MIPSEL64N32:
                case SCMP_ARCH_MIPS64N32:
                case SCMP_ARCH_MIPSEL64:
                case SCMP_ARCH_MIPS64:
#ifdef SCMP_ARCH_RISCV64
                case SCMP_ARCH_RISCV64:
#endif
                        /* These we know we support (i.e. are the ones that do not use socketcall()) */
                        supported = true;
                        break;

                case SCMP_ARCH_S390:
                case SCMP_ARCH_S390X:
                case SCMP_ARCH_X86:
                case SCMP_ARCH_MIPSEL:
                case SCMP_ARCH_MIPS:
                case SCMP_ARCH_PPC:
                case SCMP_ARCH_PPC64:
                case SCMP_ARCH_PPC64LE:
                default:
                        /* These we either know we don't support (i.e. are the ones that do use socketcall()), or we
                         * don't know */
                        supported = false;
                        break;
                }

                if (!supported)
                        continue;

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return r;

                if (allow_list) {
                        int first = 0, last = 0;
                        void *afp;

                        /* If this is an allow list, we first block the address families that are out of
                         * range and then everything that is not in the set. First, we find the lowest and
                         * highest address family in the set. */

                        SET_FOREACH(afp, address_families) {
                                int af = PTR_TO_INT(afp);

                                if (af <= 0 || af >= af_max())
                                        continue;

                                if (first == 0 || af < first)
                                        first = af;

                                if (last == 0 || af > last)
                                        last = af;
                        }

                        assert((first == 0) == (last == 0));

                        if (first == 0) {

                                /* No entries in the valid range, block everything */
                                r = seccomp_rule_add_exact(
                                                seccomp,
                                                SCMP_ACT_ERRNO(EAFNOSUPPORT),
                                                SCMP_SYS(socket),
                                                0);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to add socket() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                                        continue;
                                }

                        } else {

                                /* Block everything below the first entry */
                                r = seccomp_rule_add_exact(
                                                seccomp,
                                                SCMP_ACT_ERRNO(EAFNOSUPPORT),
                                                SCMP_SYS(socket),
                                                1,
                                                SCMP_A0(SCMP_CMP_LT, first));
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to add socket() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                                        continue;
                                }

                                /* Block everything above the last entry */
                                r = seccomp_rule_add_exact(
                                                seccomp,
                                                SCMP_ACT_ERRNO(EAFNOSUPPORT),
                                                SCMP_SYS(socket),
                                                1,
                                                SCMP_A0(SCMP_CMP_GT, last));
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to add socket() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                                        continue;
                                }

                                /* Block everything between the first and last entry */
                                for (int af = 1; af < af_max(); af++) {

                                        if (set_contains(address_families, INT_TO_PTR(af)))
                                                continue;

                                        r = seccomp_rule_add_exact(
                                                        seccomp,
                                                        SCMP_ACT_ERRNO(EAFNOSUPPORT),
                                                        SCMP_SYS(socket),
                                                        1,
                                                        SCMP_A0(SCMP_CMP_EQ, af));
                                        if (r < 0)
                                                break;
                                }
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to add socket() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                                        continue;
                                }
                        }

                } else {
                        void *af;

                        /* If this is a deny list, then generate one rule for each address family that are
                         * then combined in OR checks. */

                        SET_FOREACH(af, address_families) {
                                r = seccomp_rule_add_exact(
                                                seccomp,
                                                SCMP_ACT_ERRNO(EAFNOSUPPORT),
                                                SCMP_SYS(socket),
                                                1,
                                                SCMP_A0(SCMP_CMP_EQ, PTR_TO_INT(af)));
                                if (r < 0)
                                        break;
                        }
                        if (r < 0) {
                                log_debug_errno(r, "Failed to add socket() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                                continue;
                        }
                }

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to install socket family rules for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

int seccomp_restrict_realtime(void) {
        static const int permitted_policies[] = {
                SCHED_OTHER,
                SCHED_BATCH,
                SCHED_IDLE,
        };

        int r, max_policy = 0;
        uint32_t arch;
        unsigned i;

        /* Determine the highest policy constant we want to allow */
        for (i = 0; i < ELEMENTSOF(permitted_policies); i++)
                if (permitted_policies[i] > max_policy)
                        max_policy = permitted_policies[i];

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
                int p;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return r;

                /* Go through all policies with lower values than that, and block them -- unless they appear in the
                 * allow list. */
                for (p = 0; p < max_policy; p++) {
                        bool good = false;

                        /* Check if this is in the allow list. */
                        for (i = 0; i < ELEMENTSOF(permitted_policies); i++)
                                if (permitted_policies[i] == p) {
                                        good = true;
                                        break;
                                }

                        if (good)
                                continue;

                        /* Deny this policy */
                        r = seccomp_rule_add_exact(
                                        seccomp,
                                        SCMP_ACT_ERRNO(EPERM),
                                        SCMP_SYS(sched_setscheduler),
                                        1,
                                        SCMP_A1(SCMP_CMP_EQ, p));
                        if (r < 0) {
                                log_debug_errno(r, "Failed to add scheduler rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                                continue;
                        }
                }

                /* Deny-list all other policies, i.e. the ones with higher values. Note that all comparisons
                 * are unsigned here, hence no need no check for < 0 values. */
                r = seccomp_rule_add_exact(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(sched_setscheduler),
                                1,
                                SCMP_A1(SCMP_CMP_GT, max_policy));
                if (r < 0) {
                        log_debug_errno(r, "Failed to add scheduler rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                        continue;
                }

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to install realtime protection rules for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

static int add_seccomp_syscall_filter(scmp_filter_ctx seccomp,
                                      uint32_t arch,
                                      int nr,
                                      unsigned arg_cnt,
                                      const struct scmp_arg_cmp arg) {
        int r;

        r = seccomp_rule_add_exact(seccomp, SCMP_ACT_ERRNO(EPERM), nr, arg_cnt, arg);
        if (r < 0) {
                _cleanup_free_ char *n = NULL;

                n = seccomp_syscall_resolve_num_arch(arch, nr);
                log_debug_errno(r, "Failed to add %s() rule for architecture %s, skipping: %m",
                                strna(n),
                                seccomp_arch_to_string(arch));
        }

        return r;
}

/* For known architectures, check that syscalls are indeed defined or not. */
#if defined(__x86_64__) || defined(__arm__) || defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
assert_cc(SCMP_SYS(shmget) > 0);
assert_cc(SCMP_SYS(shmat) > 0);
assert_cc(SCMP_SYS(shmdt) > 0);
#endif

int seccomp_memory_deny_write_execute(void) {
        uint32_t arch;
        unsigned loaded = 0;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
                int filter_syscall = 0, block_syscall = 0, shmat_syscall = 0, r;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                switch (arch) {

                /* Note that on some architectures shmat() isn't available, and the call is multiplexed through ipc().
                 * We ignore that here, which means there's still a way to get writable/executable
                 * memory, if an IPC key is mapped like this. That's a pity, but no total loss. */

                case SCMP_ARCH_X86:
                case SCMP_ARCH_S390:
                        filter_syscall = SCMP_SYS(mmap2);
                        block_syscall = SCMP_SYS(mmap);
                        /* shmat multiplexed, see above */
                        break;

                case SCMP_ARCH_PPC:
                case SCMP_ARCH_PPC64:
                case SCMP_ARCH_PPC64LE:
                case SCMP_ARCH_S390X:
                        filter_syscall = SCMP_SYS(mmap);
                        /* shmat multiplexed, see above */
                        break;

                case SCMP_ARCH_ARM:
                        filter_syscall = SCMP_SYS(mmap2); /* arm has only mmap2 */
                        shmat_syscall = SCMP_SYS(shmat);
                        break;

                case SCMP_ARCH_X86_64:
                case SCMP_ARCH_X32:
                case SCMP_ARCH_AARCH64:
#ifdef SCMP_ARCH_RISCV64
                case SCMP_ARCH_RISCV64:
#endif
                        filter_syscall = SCMP_SYS(mmap); /* amd64, x32, arm64 and riscv64 have only mmap */
                        shmat_syscall = SCMP_SYS(shmat);
                        break;

                /* Please add more definitions here, if you port systemd to other architectures! */

#if !defined(__i386__) && !defined(__x86_64__) && !defined(__powerpc__) && !defined(__powerpc64__) && !defined(__arm__) && !defined(__aarch64__) && !defined(__s390__) && !defined(__s390x__) && !(defined(__riscv) && __riscv_xlen == 64)
#warning "Consider adding the right mmap() syscall definitions here!"
#endif
                }

                /* Can't filter mmap() on this arch, then skip it */
                if (filter_syscall == 0)
                        continue;

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return r;

                r = add_seccomp_syscall_filter(seccomp, arch, filter_syscall,
                                               1,
                                               SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC|PROT_WRITE, PROT_EXEC|PROT_WRITE));
                if (r < 0)
                        continue;

                if (block_syscall != 0) {
                        r = add_seccomp_syscall_filter(seccomp, arch, block_syscall, 0, (const struct scmp_arg_cmp){} );
                        if (r < 0)
                                continue;
                }

                r = add_seccomp_syscall_filter(seccomp, arch, SCMP_SYS(mprotect),
                                               1,
                                               SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC));
                if (r < 0)
                        continue;

#ifdef __NR_pkey_mprotect
                r = add_seccomp_syscall_filter(seccomp, arch, SCMP_SYS(pkey_mprotect),
                                               1,
                                               SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC));
                if (r < 0)
                        continue;
#endif

                if (shmat_syscall > 0) {
                        r = add_seccomp_syscall_filter(seccomp, arch, shmat_syscall,
                                                       1,
                                                       SCMP_A2(SCMP_CMP_MASKED_EQ, SHM_EXEC, SHM_EXEC));
                        if (r < 0)
                                continue;
                }

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to install MemoryDenyWriteExecute= rule for architecture %s, skipping: %m",
                                        seccomp_arch_to_string(arch));
                loaded++;
        }

        if (loaded == 0)
                log_debug("Failed to install any seccomp rules for MemoryDenyWriteExecute=.");

        return loaded;
}

int seccomp_restrict_archs(Set *archs) {
        _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
        int r;
        bool blocked_new = false;

        /* This installs a filter with no rules, but that restricts the system call architectures to the specified
         * list.
         *
         * There are some qualifications. However the most important use is to stop processes from bypassing
         * system call restrictions, in case they used a broader (multiplexing) syscall which is only available
         * in a non-native architecture. There are no holes in this use case, at least so far. */

        /* Note libseccomp includes our "native" (current) architecture in the filter by default.
         * We do not remove it. For example, our callers expect to be able to call execve() afterwards
         * to run a program with the restrictions applied. */
        seccomp = seccomp_init(SCMP_ACT_ALLOW);
        if (!seccomp)
                return -ENOMEM;

        for (unsigned i = 0; seccomp_local_archs[i] != SECCOMP_LOCAL_ARCH_END; ++i) {
                uint32_t arch = seccomp_local_archs[i];

                /* See above comment, our "native" architecture is never blocked. */
                if (arch == seccomp_arch_native())
                        continue;

                /* That architecture might have already been blocked by a previous call to seccomp_restrict_archs. */
                if (arch == SECCOMP_LOCAL_ARCH_BLOCKED)
                        continue;

                bool block = !set_contains(archs, UINT32_TO_PTR(arch + 1));

                /* The vdso for x32 assumes that x86-64 syscalls are available.  Let's allow them, since x32
                 * x32 syscalls should basically match x86-64 for everything except the pointer type.
                 * The important thing is that you can block the old 32-bit x86 syscalls.
                 * https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=850047 */
                if (block && arch == SCMP_ARCH_X86_64 && seccomp_arch_native() == SCMP_ARCH_X32)
                        block = !set_contains(archs, UINT32_TO_PTR(SCMP_ARCH_X32 + 1));

                if (block) {
                        seccomp_local_archs[i] = SECCOMP_LOCAL_ARCH_BLOCKED;
                        blocked_new = true;
                } else {
                        r = seccomp_arch_add(seccomp, arch);
                        if (r < 0 && r != -EEXIST)
                                return r;
                }
        }

        /* All architectures that will be blocked by the seccomp program were
         * already blocked. */
        if (!blocked_new)
                return 0;

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
        if (r < 0)
                return r;

        r = seccomp_load(seccomp);
        if (ERRNO_IS_SECCOMP_FATAL(r))
                return r;
        if (r < 0)
                log_debug_errno(r, "Failed to restrict system call architectures, skipping: %m");

        return 0;
}

int parse_syscall_archs(char **l, Set **ret_archs) {
        _cleanup_set_free_ Set *archs = NULL;
        char **s;
        int r;

        assert(l);
        assert(ret_archs);

        STRV_FOREACH(s, l) {
                uint32_t a;

                r = seccomp_arch_from_string(*s, &a);
                if (r < 0)
                        return -EINVAL;

                r = set_ensure_put(&archs, NULL, UINT32_TO_PTR(a + 1));
                if (r < 0)
                        return -ENOMEM;
        }

        *ret_archs = TAKE_PTR(archs);
        return 0;
}

int seccomp_filter_set_add(Hashmap *filter, bool add, const SyscallFilterSet *set) {
        const char *i;
        int r;

        assert(set);

        NULSTR_FOREACH(i, set->value) {

                if (i[0] == '@') {
                        const SyscallFilterSet *more;

                        more = syscall_filter_set_find(i);
                        if (!more)
                                return -ENXIO;

                        r = seccomp_filter_set_add(filter, add, more);
                        if (r < 0)
                                return r;
                } else {
                        int id;

                        id = seccomp_syscall_resolve_name(i);
                        if (id == __NR_SCMP_ERROR) {
                                log_debug("Couldn't resolve system call, ignoring: %s", i);
                                continue;
                        }

                        if (add) {
                                r = hashmap_put(filter, INT_TO_PTR(id + 1), INT_TO_PTR(-1));
                                if (r < 0)
                                        return r;
                        } else
                                (void) hashmap_remove(filter, INT_TO_PTR(id + 1));
                }
        }

        return 0;
}

int seccomp_lock_personality(unsigned long personality) {
        uint32_t arch;
        int r;

        if (personality >= PERSONALITY_INVALID)
                return -EINVAL;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return r;

                r = seccomp_rule_add_exact(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(personality),
                                1,
                                SCMP_A0(SCMP_CMP_NE, personality));
                if (r < 0) {
                        log_debug_errno(r, "Failed to add scheduler rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                        continue;
                }

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to enable personality lock for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

int seccomp_protect_hostname(void) {
        uint32_t arch;
        int r;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return r;

                r = seccomp_rule_add_exact(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(sethostname),
                                0);
                if (r < 0) {
                        log_debug_errno(r, "Failed to add sethostname() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                        continue;
                }

                r = seccomp_rule_add_exact(
                                seccomp,
                                SCMP_ACT_ERRNO(EPERM),
                                SCMP_SYS(setdomainname),
                                0);
                if (r < 0) {
                        log_debug_errno(r, "Failed to add setdomainname() rule for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
                        continue;
                }

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to apply hostname restrictions for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

static int seccomp_restrict_sxid(scmp_filter_ctx seccomp, mode_t m) {
        /* Checks the mode_t parameter of the following system calls:
         *
         *       → chmod() + fchmod() + fchmodat()
         *       → open() + creat() + openat()
         *       → mkdir() + mkdirat()
         *       → mknod() + mknodat()
         *
         * Returns error if *everything* failed, and 0 otherwise.
         */
        int r;
        bool any = false;

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(chmod),
                        1,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for chmod: %m");
        else
                any = true;

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(fchmod),
                        1,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for fchmod: %m");
        else
                any = true;

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(fchmodat),
                        1,
                        SCMP_A2(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for fchmodat: %m");
        else
                any = true;

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(mkdir),
                        1,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for mkdir: %m");
        else
                any = true;

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(mkdirat),
                        1,
                        SCMP_A2(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for mkdirat: %m");
        else
                any = true;

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(mknod),
                        1,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for mknod: %m");
        else
                any = true;

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(mknodat),
                        1,
                        SCMP_A2(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for mknodat: %m");
        else
                any = true;

#if SCMP_SYS(open) > 0
        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(open),
                        2,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT),
                        SCMP_A2(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for open: %m");
        else
                any = true;
#endif

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(openat),
                        2,
                        SCMP_A2(SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT),
                        SCMP_A3(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for openat: %m");
        else
                any = true;

#if defined(__SNR_openat2)
        /* The new openat2() system call can't be filtered sensibly, since it moves the flags parameter into
         * an indirect structure. Let's block it entirely for now. That should be a reasonably OK thing to do
         * for now, since openat2() is very new and code generally needs fallback logic anyway to be
         * compatible with kernels that are not absolutely recent. We would normally return EPERM for a
         * policy check, but this isn't strictly a policy check. Instead, we return ENOSYS to force programs
         * to call open() or openat() instead. We can properly enforce policy for those functions. */
        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(ENOSYS),
                        SCMP_SYS(openat2),
                        0);
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for openat2: %m");
        else
                any = true;
#endif

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(creat),
                        1,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, m, m));
        if (r < 0)
                log_debug_errno(r, "Failed to add filter for creat: %m");
        else
                any = true;

        return any ? 0 : r;
}

int seccomp_restrict_suid_sgid(void) {
        uint32_t arch;
        int r, k;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return r;

                r = seccomp_restrict_sxid(seccomp, S_ISUID);
                if (r < 0)
                        log_debug_errno(r, "Failed to add suid rule for architecture %s, ignoring: %m", seccomp_arch_to_string(arch));

                k = seccomp_restrict_sxid(seccomp, S_ISGID);
                if (k < 0)
                        log_debug_errno(r, "Failed to add sgid rule for architecture %s, ignoring: %m", seccomp_arch_to_string(arch));

                if (r < 0 && k < 0)
                        continue;

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to apply suid/sgid restrictions for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

uint32_t scmp_act_kill_process(void) {

        /* Returns SCMP_ACT_KILL_PROCESS if it's supported, and SCMP_ACT_KILL_THREAD otherwise. We never
         * actually want to use SCMP_ACT_KILL_THREAD as its semantics are nuts (killing arbitrary threads of
         * a program is just a bad idea), but on old kernels/old libseccomp it is all we have, and at least
         * for single-threaded apps does the right thing. */

#ifdef SCMP_ACT_KILL_PROCESS
        if (seccomp_api_get() >= 3)
                return SCMP_ACT_KILL_PROCESS;
#endif

        return SCMP_ACT_KILL; /* same as SCMP_ACT_KILL_THREAD */
}

int parse_syscall_and_errno(const char *in, char **name, int *error) {
        _cleanup_free_ char *n = NULL;
        char *p;
        int e = -1;

        assert(in);
        assert(name);
        assert(error);

        /*
         * This parse "syscall:errno" like "uname:EILSEQ", "@sync:255".
         * If errno is omitted, then error is set to -1.
         * Empty syscall name is not allowed.
         * Here, we do not check that the syscall name is valid or not.
         */

        p = strchr(in, ':');
        if (p) {
                e = seccomp_parse_errno_or_action(p + 1);
                if (e < 0)
                        return e;

                n = strndup(in, p - in);
        } else
                n = strdup(in);

        if (!n)
                return -ENOMEM;

        if (isempty(n))
                return -EINVAL;

        *error = e;
        *name = TAKE_PTR(n);

        return 0;
}
