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
#endif
#include "string-util.h"
#include "strv.h"

#ifdef HAVE_SECCOMP

static int seccomp_add_default_syscall_filter(
                scmp_filter_ctx ctx,
                uint32_t arch,
                uint64_t cap_list_retain,
                char **syscall_whitelist,
                char **syscall_blacklist) {

        static const struct {
                uint64_t capability;
                const char* name;
        } blacklist[] = {
                { 0,              "@obsolete"           },
                { 0,              "@keyring"            }, /* keyring is not namespaced */
                { 0,              "bpf"                 },
                { 0,              "kexec_file_load"     },
                { 0,              "kexec_load"          },
                { 0,              "lookup_dcookie"      },
                { 0,              "open_by_handle_at"   },
                { 0,              "perf_event_open"     },
                { 0,              "quotactl"            },
                { 0,              "@swap"               },
                { CAP_SYSLOG,     "syslog"              },
                { CAP_SYS_MODULE, "@module"             },
                { CAP_SYS_PACCT,  "acct"                },
                { CAP_SYS_PTRACE, "process_vm_readv"    },
                { CAP_SYS_PTRACE, "process_vm_writev"   },
                { CAP_SYS_PTRACE, "ptrace"              },
                { CAP_SYS_RAWIO,  "@raw-io"             },
                { CAP_SYS_TIME,   "@clock"              },
        };

        int r, c = 0;
        size_t i;
        char **p;

        for (i = 0; i < ELEMENTSOF(blacklist); i++) {
                if (blacklist[i].capability != 0 && (cap_list_retain & (1ULL << blacklist[i].capability)))
                        continue;

                r = seccomp_add_syscall_filter_item(ctx, blacklist[i].name, SCMP_ACT_ERRNO(EPERM), syscall_whitelist);
                if (r < 0)
                        /* If the system call is not known on this architecture, then that's fine, let's ignore it */
                        log_debug_errno(r, "Failed to add rule for system call %s, ignoring: %m", blacklist[i].name);
                else
                        c++;
        }

        STRV_FOREACH(p, syscall_blacklist) {
                r = seccomp_add_syscall_filter_item(ctx, *p, SCMP_ACT_ERRNO(EPERM), syscall_whitelist);
                if (r < 0)
                        log_debug_errno(r, "Failed to add rule for system call %s, ignoring: %m", *p);
                else
                        c++;
        }

        return c;
}

int setup_seccomp(uint64_t cap_list_retain, char **syscall_whitelist, char **syscall_blacklist) {
        uint32_t arch;
        int r;

        if (!is_seccomp_available()) {
                log_debug("SECCOMP features not detected in the kernel, disabling SECCOMP filterering");
                return 0;
        }

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
                int n;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate seccomp object: %m");

                n = seccomp_add_default_syscall_filter(seccomp, arch, cap_list_retain, syscall_whitelist, syscall_blacklist);
                if (n < 0)
                        return n;

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

int setup_seccomp(uint64_t cap_list_retain, char **syscall_whitelist, char **syscall_blacklist) {
        return 0;
}

#endif
