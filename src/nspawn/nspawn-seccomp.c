/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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
#include <linux/netlink.h>
#include <sys/capability.h>
#include <sys/types.h>

#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif

#include "alloc-util.h"
#include "log.h"
#include "nspawn-seccomp.h"

#ifdef HAVE_SECCOMP
#include "seccomp-util.h"
#include "string-util.h"
#include "strv.h"
#endif

#ifdef HAVE_SECCOMP

static const SyscallFilterSet nspawn_default_blacklist = {
        .name = "@nspawn_default_blacklist",
        .help = "Syscall filter for systemd-nspawn",
        .value =
        "_sysctl\0"
        "add_key\0"
        "afs_syscall\0"
        "bdflush\0"
#ifdef __NR_bpf
        "bpf\0"
#endif
        "break\0"
        "create_module\0"
        "ftime\0"
        "get_kernel_syms\0"
        "getpmsg\0"
        "gtty\0"
#ifdef __NR_kexec_file_load
        "kexec_file_load\0"
#endif
        "kexec_load\0"
        "keyctl\0"
        "lock\0"
        "lookup_dcookie\0"
        "mpx\0"
        "nfsservctl\0"
        "open_by_handle_at\0"
        "perf_event_open\0"
        "prof\0"
        "profil\0"
        "putpmsg\0"
        "query_module\0"
        "quotactl\0"
        "request_key\0"
        "security\0"
        "sgetmask\0"
        "ssetmask\0"
        "stty\0"
        "swapoff\0"
        "swapon\0"
        "sysfs\0"
        "tuxcall\0"
        "ulimit\0"
        "uselib\0"
        "ustat\0"
        "vserver\0"
};

static int seccomp_add_syscall_filter_capabilities(
                Set *blacklist,
                uint64_t cap_list_retain) {

        struct {
                uint64_t capability;
                SyscallFilterSet set;
        } cap_filter_sets[] = {
                { CAP_SYS_MODULE,       syscall_filter_sets[SYSCALL_FILTER_SET_MODULE]},
                { CAP_SYS_RAWIO,        syscall_filter_sets[SYSCALL_FILTER_SET_RAW_IO]},
                { CAP_SYS_TIME,         syscall_filter_sets[SYSCALL_FILTER_SET_CLOCK]},
                { CAP_SYSLOG,           { .value = "syslog\0"   }},
                { CAP_SYS_PACCT,        { .value = "acct\0"     }},
                { CAP_SYS_PTRACE,       { .value =
                                        "process_vm_readv\0"
                                        "process_vm_writev\0"
                                        "ptrace\0"              }},
        };
        int r;
        unsigned i;

        for (i = 0; i < ELEMENTSOF(cap_filter_sets); i++) {
                /* skip if we need to retain the capability */
                if (cap_list_retain & (1ULL << cap_filter_sets[i].capability))
                        continue;

                r = seccomp_filter_set_add(blacklist, true, &(cap_filter_sets[i].set));
                if (r < 0)
                        log_debug_errno(r, "Failed to add capability to blacklist, ignoring: %m");
        }

        return 0;
}

static int seccomp_setup_filter(
                scmp_filter_ctx ctx,
                Set *blacklist,
                uint64_t cap_list_retain,
                Set *syscall_filter,
                bool iswhitelist
                ) {
        int r;

        /* parse the default blacklist */
        r = seccomp_filter_set_add(blacklist, true, &nspawn_default_blacklist);
        if (r < 0)
                return log_debug_errno(r, "Failed to add default filter to blacklist: %m");

        /* Filter out syscalls by capabilities but retain the ones on the list */
        r = seccomp_add_syscall_filter_capabilities(blacklist, cap_list_retain);
        if (r < 0)
                return r;

        /* apply the custom filter */
        if (syscall_filter) {
                Iterator i;
                char *t;

                SET_FOREACH(t, syscall_filter, i) {
                        if (t[0] == '@') {
                                const SyscallFilterSet *more;

                                more = syscall_filter_set_find(t);
                                if (!more)
                                        return -EINVAL;

                                r = seccomp_filter_set_add(blacklist, !iswhitelist, more);
                                if (r < 0)
                                        return r;
                        } else {
                                int id;

                                id = seccomp_syscall_resolve_name(t);
                                if (id == __NR_SCMP_ERROR)
                                        return log_debug_errno(-ENXIO, "Couldn't resolve syscall %s() / %d: %m", t, PTR_TO_INT(id) - 1);

                                if (!iswhitelist) {
                                        r = set_put(blacklist, INT_TO_PTR(id + 1));
                                        if (r < 0)
                                                return r;
                                        log_debug("Added syscall to default blacklist: %s()", t);
                                } else
                                        (void) set_remove(blacklist, INT_TO_PTR(id + 1));
                                        log_debug("Removed syscall from default blacklist: %s()", t);
                        }
                }
        }

        return 0;
}

int setup_seccomp(uint64_t cap_list_retain, Set *syscall_filter, bool iswhitelist) {
        uint32_t arch;
        int r;

        if (!is_seccomp_available()) {
                log_debug("SECCOMP features not detected in the kernel, disabling SECCOMP audit filter");
                return 0;
        }

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
                Set *blacklist = set_new(NULL);
                int n;
                Iterator i;
                void *id;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate seccomp object: %m");

                n = seccomp_setup_filter(seccomp, blacklist, cap_list_retain, syscall_filter, iswhitelist);
                if (n < 0)
                        return log_error_errno(n, "Failed to set up filter: %m");

                SET_FOREACH(id, blacklist, i) {
                        r = seccomp_rule_add_exact(seccomp, SCMP_ACT_ERRNO(EPERM), PTR_TO_INT(id) - 1, 0);
                        if (r < 0) {
                                /* If the system call is not known on this architecture, then that's fine, let's ignore it */
                                char *id_n = NULL;

                                id_n = seccomp_syscall_resolve_num_arch(arch, PTR_TO_INT(id) - 1);
                                log_debug_errno(r, "Failed to add rule for system call %s() / %d, ignoring: %m", strna(id_n), PTR_TO_INT(id) - 1);
                        }
                }

                /*
                  Audit is broken in containers, much of the userspace audit hookup will fail if running inside a
                  container. We don't care and just turn off creation of audit sockets.

                  This will make socket(AF_NETLINK, *, NETLINK_AUDIT) fail with EAFNOSUPPORT which audit userspace uses
                  as indication that audit is disabled in the kernel.
                */

                r = seccomp_rule_add_exact(
                                seccomp,
                                SCMP_ACT_ERRNO(EAFNOSUPPORT),
                                SCMP_SYS(socket),
                                2,
                                SCMP_A0(SCMP_CMP_EQ, AF_NETLINK),
                                SCMP_A2(SCMP_CMP_EQ, NETLINK_AUDIT));
                if (r < 0)
                        log_debug_errno(r, "Failed to add audit seccomp rule, ignoring: %m");
                else
                        n++;

                if (n <= 0) /* no rule added? then skip this architecture */
                        continue;

                r = seccomp_load(seccomp);
                if (IN_SET(r, -EPERM, -EACCES))
                        return log_error_errno(r, "Failed to install seccomp audit filter: %m");
                if (r < 0)
                        log_debug_errno(r, "Failed to install filter set for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

#else

int setup_seccomp(uint64_t cap_list_retain, Set *syscall_filter, bool iswhitelist) {
        return 0;
}

#endif
