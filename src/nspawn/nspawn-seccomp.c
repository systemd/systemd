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

#include "log.h"

#ifdef HAVE_SECCOMP
#include "seccomp-util.h"
#endif

#include "nspawn-seccomp.h"

#ifdef HAVE_SECCOMP

static int seccomp_add_default_syscall_filter(scmp_filter_ctx ctx,
                                              uint64_t cap_list_retain) {
        unsigned i;
        int r;
        static const struct {
                uint64_t capability;
                int syscall_num;
        } blacklist[] = {
                { CAP_SYS_RAWIO,  SCMP_SYS(iopl)              },
                { CAP_SYS_RAWIO,  SCMP_SYS(ioperm)            },
                { CAP_SYS_BOOT,   SCMP_SYS(kexec_load)        },
                { CAP_SYS_ADMIN,  SCMP_SYS(swapon)            },
                { CAP_SYS_ADMIN,  SCMP_SYS(swapoff)           },
                { CAP_SYS_ADMIN,  SCMP_SYS(open_by_handle_at) },
                { CAP_SYS_MODULE, SCMP_SYS(init_module)       },
                { CAP_SYS_MODULE, SCMP_SYS(finit_module)      },
                { CAP_SYS_MODULE, SCMP_SYS(delete_module)     },
                { CAP_SYSLOG,     SCMP_SYS(syslog)            },
        };

        for (i = 0; i < ELEMENTSOF(blacklist); i++) {
                if (cap_list_retain & (1ULL << blacklist[i].capability))
                        continue;

                r = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), blacklist[i].syscall_num, 0);
                if (r == -EFAULT)
                        continue; /* unknown syscall */
                if (r < 0) {
                        log_error_errno(r, "Failed to block syscall: %m");
                        return r;
                }
        }

        return 0;
}

int setup_seccomp(uint64_t cap_list_retain) {
        scmp_filter_ctx seccomp;
        int r;

        seccomp = seccomp_init(SCMP_ACT_ALLOW);
        if (!seccomp)
                return log_oom();

        r = seccomp_add_secondary_archs(seccomp);
        if (r < 0) {
                log_error_errno(r, "Failed to add secondary archs to seccomp filter: %m");
                goto finish;
        }

        r = seccomp_add_default_syscall_filter(seccomp, cap_list_retain);
        if (r < 0)
                goto finish;

        /*
           Audit is broken in containers, much of the userspace audit
           hookup will fail if running inside a container. We don't
           care and just turn off creation of audit sockets.

           This will make socket(AF_NETLINK, *, NETLINK_AUDIT) fail
           with EAFNOSUPPORT which audit userspace uses as indication
           that audit is disabled in the kernel.
         */

        r = seccomp_rule_add(
                        seccomp,
                        SCMP_ACT_ERRNO(EAFNOSUPPORT),
                        SCMP_SYS(socket),
                        2,
                        SCMP_A0(SCMP_CMP_EQ, AF_NETLINK),
                        SCMP_A2(SCMP_CMP_EQ, NETLINK_AUDIT));
        if (r < 0) {
                log_error_errno(r, "Failed to add audit seccomp rule: %m");
                goto finish;
        }

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
        if (r < 0) {
                log_error_errno(r, "Failed to unset NO_NEW_PRIVS: %m");
                goto finish;
        }

        r = seccomp_load(seccomp);
        if (r == -EINVAL) {
                log_debug_errno(r, "Kernel is probably not configured with CONFIG_SECCOMP. Disabling seccomp audit filter: %m");
                r = 0;
                goto finish;
        }
        if (r < 0) {
                log_error_errno(r, "Failed to install seccomp audit filter: %m");
                goto finish;
        }

finish:
        seccomp_release(seccomp);
        return r;
}

#else

int setup_seccomp(uint64_t cap_list_retain) {
        return 0;
}

#endif
