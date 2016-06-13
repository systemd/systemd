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

#include "macro.h"
#include "seccomp-util.h"
#include "string-util.h"

const char* seccomp_arch_to_string(uint32_t c) {

        if (c == SCMP_ARCH_NATIVE)
                return "native";
        if (c == SCMP_ARCH_X86)
                return "x86";
        if (c == SCMP_ARCH_X86_64)
                return "x86-64";
        if (c == SCMP_ARCH_X32)
                return "x32";
        if (c == SCMP_ARCH_ARM)
                return "arm";

        return NULL;
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
        else
                return -EINVAL;

        return 0;
}

int seccomp_add_secondary_archs(scmp_filter_ctx *c) {

#if defined(__i386__) || defined(__x86_64__)
        int r;

        /* Add in all possible secondary archs we are aware of that
         * this kernel might support. */

        r = seccomp_arch_add(c, SCMP_ARCH_X86);
        if (r < 0 && r != -EEXIST)
                return r;

        r = seccomp_arch_add(c, SCMP_ARCH_X86_64);
        if (r < 0 && r != -EEXIST)
                return r;

        r = seccomp_arch_add(c, SCMP_ARCH_X32);
        if (r < 0 && r != -EEXIST)
                return r;

#endif

        return 0;

}

const SystemCallFilterSet syscall_filter_sets[] = {
        {
                /* Clock */
                .set_name = "@clock",
                .value =
                "adjtimex\0"
                "clock_adjtime\0"
                "clock_settime\0"
                "settimeofday\0"
                "stime\0"
        }, {
                /* CPU emulation calls */
                .set_name = "@cpu-emulation",
                .value =
                "modify_ldt\0"
                "subpage_prot\0"
                "switch_endian\0"
                "vm86\0"
                "vm86old\0"
        }, {
                /* Debugging/Performance Monitoring/Tracing */
                .set_name = "@debug",
                .value =
                "lookup_dcookie\0"
                "perf_event_open\0"
                "process_vm_readv\0"
                "process_vm_writev\0"
                "ptrace\0"
                "rtas\0"
                "s390_runtime_instr\0"
                "sys_debug_setcontext\0"
        }, {
                /* Default list */
                .set_name = "@default",
                .value =
                "execve\0"
                "exit\0"
                "exit_group\0"
                "rt_sigreturn\0"
                "sigreturn\0"
        }, {
                /* Event loop use */
                .set_name = "@io-event",
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
        }, {
                /* Message queues, SYSV IPC or other IPC: unusual */
                .set_name = "@ipc",
                .value = "ipc\0"
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
        }, {
                /* Keyring */
                .set_name = "@keyring",
                .value =
                "add_key\0"
                "keyctl\0"
                "request_key\0"
        }, {
                /* Kernel module control */
                .set_name = "@module",
                .value =
                "delete_module\0"
                "finit_module\0"
                "init_module\0"
        }, {
                /* Mounting */
                .set_name = "@mount",
                .value =
                "chroot\0"
                "mount\0"
                "oldumount\0"
                "pivot_root\0"
                "umount2\0"
                "umount\0"
        }, {
                /* Network or Unix socket IO, should not be needed if not network facing */
                .set_name = "@network-io",
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
        }, {
                /* Unusual, obsolete or unimplemented, some unknown even to libseccomp */
                .set_name = "@obsolete",
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
        }, {
                /* Nice grab-bag of all system calls which need superuser capabilities */
                .set_name = "@privileged",
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
                "sysctl\0"
                "vhangup\0"
        }, {
                /* Process control, execution, namespaces */
                .set_name = "@process",
                .value =
                "arch_prctl\0"
                "clone\0"
                "execve\0"
                "execveat\0"
                "fork\0"
                "kill\0"
                "prctl\0"
                "setns\0"
                "tgkill\0"
                "tkill\0"
                "unshare\0"
                "vfork\0"
        }, {
                /* Raw I/O ports */
                .set_name = "@raw-io",
                .value =
                "ioperm\0"
                "iopl\0"
                "pciconfig_iobase\0"
                "pciconfig_read\0"
                "pciconfig_write\0"
                "s390_pci_mmio_read\0"
                "s390_pci_mmio_write\0"
        }, {
                .set_name = NULL,
                .value = NULL
        }
};
