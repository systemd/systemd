/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <linux/netlink.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/types.h>

#if HAVE_SECCOMP
#include <seccomp.h>
#endif

#include "alloc-util.h"
#include "log.h"
#include "nspawn-seccomp.h"
#if HAVE_SECCOMP
#include "seccomp-util.h"
#endif
#include "string-util.h"
#include "strv.h"

#if HAVE_SECCOMP

static int seccomp_add_default_syscall_filter(
                scmp_filter_ctx ctx,
                uint32_t arch,
                uint64_t cap_list_retain,
                char **syscall_whitelist,
                char **syscall_blacklist) {

        static const struct {
                uint64_t capability;
                const char* name;
        } whitelist[] = {
                /* Let's use set names where we can */
                { 0,                  "@aio"                   },
                { 0,                  "@basic-io"              },
                { 0,                  "@chown"                 },
                { 0,                  "@default"               },
                { 0,                  "@file-system"           },
                { 0,                  "@io-event"              },
                { 0,                  "@ipc"                   },
                { 0,                  "@mount"                 },
                { 0,                  "@network-io"            },
                { 0,                  "@process"               },
                { 0,                  "@resources"             },
                { 0,                  "@setuid"                },
                { 0,                  "@signal"                },
                { 0,                  "@sync"                  },
                { 0,                  "@timer"                 },

                /* The following four are sets we optionally enable, in case the caps have been configured for it */
                { CAP_SYS_TIME,       "@clock"                 },
                { CAP_SYS_MODULE,     "@module"                },
                { CAP_SYS_RAWIO,      "@raw-io"                },
                { CAP_IPC_LOCK,       "@memlock"               },

                /* Plus a good set of additional syscalls which are not part of any of the groups above */
                { 0,                  "brk"                    },
                { 0,                  "capget"                 },
                { 0,                  "capset"                 },
                { 0,                  "copy_file_range"        },
                { 0,                  "fadvise64"              },
                { 0,                  "fadvise64_64"           },
                { 0,                  "flock"                  },
                { 0,                  "get_mempolicy"          },
                { 0,                  "getcpu"                 },
                { 0,                  "getpriority"            },
                { 0,                  "getrandom"              },
                { 0,                  "ioctl"                  },
                { 0,                  "ioprio_get"             },
                { 0,                  "kcmp"                   },
                { 0,                  "madvise"                },
                { 0,                  "mincore"                },
                { 0,                  "mprotect"               },
                { 0,                  "mremap"                 },
                { 0,                  "name_to_handle_at"      },
                { 0,                  "oldolduname"            },
                { 0,                  "olduname"               },
                { 0,                  "personality"            },
                { 0,                  "readahead"              },
                { 0,                  "readdir"                },
                { 0,                  "remap_file_pages"       },
                { 0,                  "sched_get_priority_max" },
                { 0,                  "sched_get_priority_min" },
                { 0,                  "sched_getaffinity"      },
                { 0,                  "sched_getattr"          },
                { 0,                  "sched_getparam"         },
                { 0,                  "sched_getscheduler"     },
                { 0,                  "sched_rr_get_interval"  },
                { 0,                  "sched_yield"            },
                { 0,                  "seccomp"                },
                { 0,                  "sendfile"               },
                { 0,                  "sendfile64"             },
                { 0,                  "setdomainname"          },
                { 0,                  "setfsgid"               },
                { 0,                  "setfsgid32"             },
                { 0,                  "setfsuid"               },
                { 0,                  "setfsuid32"             },
                { 0,                  "sethostname"            },
                { 0,                  "setpgid"                },
                { 0,                  "setsid"                 },
                { 0,                  "splice"                 },
                { 0,                  "sysinfo"                },
                { 0,                  "tee"                    },
                { 0,                  "umask"                  },
                { 0,                  "uname"                  },
                { 0,                  "userfaultfd"            },
                { 0,                  "vmsplice"               },

                /* The following individual syscalls are added depending on specified caps */
                { CAP_SYS_PACCT,      "acct"                   },
                { CAP_SYS_PTRACE,     "process_vm_readv"       },
                { CAP_SYS_PTRACE,     "process_vm_writev"      },
                { CAP_SYS_PTRACE,     "ptrace"                 },
                { CAP_SYS_BOOT,       "reboot"                 },
                { CAP_SYSLOG,         "syslog"                 },
                { CAP_SYS_TTY_CONFIG, "vhangup"                },

                /*
                 * The following syscalls and groups are knowingly excluded:
                 *
                 * @cpu-emulation
                 * @keyring           (NB: keyring is not namespaced!)
                 * @obsolete
                 * @swap
                 *
                 * bpf                (NB: bpffs is not namespaced!)
                 * fanotify_init
                 * fanotify_mark
                 * kexec_file_load
                 * kexec_load
                 * lookup_dcookie
                 * nfsservctl
                 * open_by_handle_at
                 * perf_event_open
                 * pkey_alloc
                 * pkey_free
                 * pkey_mprotect
                 * quotactl
                 */
        };

        int r;
        size_t i;
        char **p;

        for (i = 0; i < ELEMENTSOF(whitelist); i++) {
                if (whitelist[i].capability != 0 && (cap_list_retain & (1ULL << whitelist[i].capability)) == 0)
                        continue;

                r = seccomp_add_syscall_filter_item(ctx, whitelist[i].name, SCMP_ACT_ALLOW, syscall_blacklist, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to add syscall filter item %s: %m", whitelist[i].name);
        }

        STRV_FOREACH(p, syscall_whitelist) {
                r = seccomp_add_syscall_filter_item(ctx, *p, SCMP_ACT_ALLOW, syscall_blacklist, false);
                if (r < 0)
                        log_warning_errno(r, "Failed to add rule for system call %s on %s, ignoring: %m",
                                          *p, seccomp_arch_to_string(arch));
        }

        return 0;
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

                log_debug("Applying whitelist on architecture: %s", seccomp_arch_to_string(arch));

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ERRNO(EPERM));
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate seccomp object: %m");

                r = seccomp_add_default_syscall_filter(seccomp, arch, cap_list_retain, syscall_whitelist, syscall_blacklist);
                if (r < 0)
                        return r;

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
                        return log_error_errno(r, "Failed to install seccomp filter: %m");
                if (r < 0)
                        log_debug_errno(r, "Failed to install filter set for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;

                log_debug("Applying NETLINK_AUDIT mask on architecture: %s", seccomp_arch_to_string(arch));

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate seccomp object: %m");

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
                if (r < 0) {
                        log_debug_errno(r, "Failed to add audit seccomp rule, ignoring: %m");
                        continue;
                }

                r = seccomp_load(seccomp);
                if (ERRNO_IS_SECCOMP_FATAL(r))
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
