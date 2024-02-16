/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

#include "af-list.h"
#include "analyze.h"
#include "analyze-security.h"
#include "analyze-verify.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "copy.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "in-addr-prefix-util.h"
#include "locale-util.h"
#include "macro.h"
#include "manager.h"
#include "missing_capability.h"
#include "missing_sched.h"
#include "mkdir.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "seccomp-util.h"
#include "service.h"
#include "set.h"
#include "stdio-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "unit-serialize.h"

typedef struct SecurityInfo {
        char *id;
        char *type;
        char *load_state;
        char *fragment_path;
        bool default_dependencies;

        uint64_t ambient_capabilities;
        uint64_t capability_bounding_set;

        char *user;
        char **supplementary_groups;
        bool dynamic_user;

        bool ip_address_deny_all;
        bool ip_address_allow_localhost;
        bool ip_address_allow_other;

        bool ip_filters_custom_ingress;
        bool ip_filters_custom_egress;

        char *keyring_mode;
        char *protect_proc;
        char *proc_subset;
        bool lock_personality;
        bool memory_deny_write_execute;
        bool no_new_privileges;
        char *notify_access;
        bool protect_hostname;

        bool private_devices;
        bool private_mounts;
        bool private_network;
        bool private_tmp;
        bool private_users;

        bool protect_control_groups;
        bool protect_kernel_modules;
        bool protect_kernel_tunables;
        bool protect_kernel_logs;
        bool protect_clock;

        char *protect_home;
        char *protect_system;

        bool remove_ipc;

        bool restrict_address_family_inet;
        bool restrict_address_family_unix;
        bool restrict_address_family_netlink;
        bool restrict_address_family_packet;
        bool restrict_address_family_other;

        unsigned long long restrict_namespaces;
        bool restrict_realtime;
        bool restrict_suid_sgid;

        char *root_directory;
        char *root_image;

        bool delegate;
        char *device_policy;
        char **device_allow;

        Set *system_call_architectures;

        bool system_call_filter_allow_list;
        Set *system_call_filter;

        mode_t _umask;
} SecurityInfo;

struct security_assessor {
        const char *id;
        const char *json_field;
        const char *description_good;
        const char *description_bad;
        const char *description_na;
        const char *url;
        uint64_t weight;
        uint64_t range;
        int (*assess)(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description);
        size_t offset;
        uint64_t parameter;
        bool default_dependencies_only;
};

static SecurityInfo *security_info_new(void) {
        SecurityInfo *info = new(SecurityInfo, 1);
        if (!info)
                return NULL;

        *info = (SecurityInfo) {
                .default_dependencies = true,
                .capability_bounding_set = UINT64_MAX,
                .restrict_namespaces = UINT64_MAX,
                ._umask = 0002,
        };

        return info;
}

static SecurityInfo *security_info_free(SecurityInfo *i) {
        if (!i)
                return NULL;

        free(i->id);
        free(i->type);
        free(i->load_state);
        free(i->fragment_path);

        free(i->user);

        free(i->protect_home);
        free(i->protect_system);

        free(i->root_directory);
        free(i->root_image);

        free(i->keyring_mode);
        free(i->protect_proc);
        free(i->proc_subset);
        free(i->notify_access);

        free(i->device_policy);
        strv_free(i->device_allow);

        strv_free(i->supplementary_groups);
        set_free(i->system_call_architectures);
        set_free(i->system_call_filter);

        return mfree(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SecurityInfo*, security_info_free);

static bool security_info_runs_privileged(const SecurityInfo *i)  {
        assert(i);

        if (STRPTR_IN_SET(i->user, "0", "root"))
                return true;

        if (i->dynamic_user)
                return false;

        return isempty(i->user);
}

static int assess_bool(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        const bool *b = ASSERT_PTR(data);

        assert(ret_badness);
        assert(ret_description);

        *ret_badness = a->parameter ? *b : !*b;
        *ret_description = NULL;

        return 0;
}

static int assess_user(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        _cleanup_free_ char *d = NULL;
        uint64_t b;

        assert(ret_badness);
        assert(ret_description);

        if (streq_ptr(info->user, NOBODY_USER_NAME)) {
                d = strdup("Service runs under as '" NOBODY_USER_NAME "' user, which should not be used for services");
                b = 9;
        } else if (info->dynamic_user && !STR_IN_SET(info->user, "0", "root")) {
                d = strdup("Service runs under a transient non-root user identity");
                b = 0;
        } else if (info->user && !STR_IN_SET(info->user, "0", "root", "")) {
                d = strdup("Service runs under a static non-root user identity");
                b = 0;
        } else {
                *ret_badness = 10;
                *ret_description = NULL;
                return 0;
        }

        if (!d)
                return log_oom();

        *ret_badness = b;
        *ret_description = TAKE_PTR(d);

        return 0;
}

static int assess_protect_home(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        const char *description;
        uint64_t badness;
        char *copy;
        int r;

        assert(ret_badness);
        assert(ret_description);

        badness = 10;
        description = "Service has full access to home directories";

        r = parse_boolean(info->protect_home);
        if (r < 0) {
                if (streq_ptr(info->protect_home, "read-only")) {
                        badness = 5;
                        description = "Service has read-only access to home directories";
                } else if (streq_ptr(info->protect_home, "tmpfs")) {
                        badness = 1;
                        description = "Service has access to fake empty home directories";
                }
        } else if (r > 0) {
                badness = 0;
                description = "Service has no access to home directories";
        }

        copy = strdup(description);
        if (!copy)
                return log_oom();

        *ret_badness = badness;
        *ret_description = copy;

        return 0;
}

static int assess_protect_system(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        const char *description;
        uint64_t badness;
        char *copy;
        int r;

        assert(ret_badness);
        assert(ret_description);

        badness = 10;
        description = "Service has full access to the OS file hierarchy";

        r = parse_boolean(info->protect_system);
        if (r < 0) {
                if (streq_ptr(info->protect_system, "full")) {
                        badness = 3;
                        description = "Service has very limited write access to the OS file hierarchy";
                } else if (streq_ptr(info->protect_system, "strict")) {
                        badness = 0;
                        description = "Service has strict read-only access to the OS file hierarchy";
                }
        } else if (r > 0) {
                badness = 5;
                description = "Service has limited write access to the OS file hierarchy";
        }

        copy = strdup(description);
        if (!copy)
                return log_oom();

        *ret_badness = badness;
        *ret_description = copy;

        return 0;
}

static int assess_root_directory(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness =
                empty_or_root(info->root_directory) &&
                empty_or_root(info->root_image);
        *ret_description = NULL;

        return 0;
}

static int assess_capability_bounding_set(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness = !!(info->capability_bounding_set & a->parameter);
        *ret_description = NULL;

        return 0;
}

static int assess_umask(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        char *copy = NULL;
        const char *d;
        uint64_t b;

        assert(ret_badness);
        assert(ret_description);

        if (!FLAGS_SET(info->_umask, 0002)) {
                d = "Files created by service are world-writable by default";
                b = 10;
        } else if (!FLAGS_SET(info->_umask, 0004)) {
                d = "Files created by service are world-readable by default";
                b = 5;
        } else if (!FLAGS_SET(info->_umask, 0020)) {
                d = "Files created by service are group-writable by default";
                b = 2;
        } else if (!FLAGS_SET(info->_umask, 0040)) {
                d = "Files created by service are group-readable by default";
                b = 1;
        } else {
                d = "Files created by service are accessible only by service's own user by default";
                b = 0;
        }

        copy = strdup(d);
        if (!copy)
                return log_oom();

        *ret_badness = b;
        *ret_description = copy;

        return 0;
}

static int assess_keyring_mode(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness = !streq_ptr(info->keyring_mode, "private");
        *ret_description = NULL;

        return 0;
}

static int assess_protect_proc(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        if (streq_ptr(info->protect_proc, "noaccess"))
                *ret_badness = 1;
        else if (STRPTR_IN_SET(info->protect_proc, "invisible", "ptraceable"))
                *ret_badness = 0;
        else
                *ret_badness = 3;

        *ret_description = NULL;

        return 0;
}

static int assess_proc_subset(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness = !streq_ptr(info->proc_subset, "pid");
        *ret_description = NULL;

        return 0;
}

static int assess_notify_access(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness = streq_ptr(info->notify_access, "all");
        *ret_description = NULL;

        return 0;
}

static int assess_remove_ipc(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        if (security_info_runs_privileged(info))
                *ret_badness = UINT64_MAX;
        else
                *ret_badness = !info->remove_ipc;

        *ret_description = NULL;
        return 0;
}

static int assess_supplementary_groups(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        if (security_info_runs_privileged(info))
                *ret_badness = UINT64_MAX;
        else
                *ret_badness = !strv_isempty(info->supplementary_groups);

        *ret_description = NULL;
        return 0;
}

static int assess_restrict_namespaces(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness = !!(info->restrict_namespaces & a->parameter);
        *ret_description = NULL;

        return 0;
}

#if HAVE_SECCOMP

static int assess_system_call_architectures(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        char *d;
        uint64_t b;

        assert(ret_badness);
        assert(ret_description);

        if (set_isempty(info->system_call_architectures)) {
                b = 10;
                d = strdup("Service may execute system calls with all ABIs");
        } else if (set_contains(info->system_call_architectures, "native") &&
                   set_size(info->system_call_architectures) == 1) {
                b = 0;
                d = strdup("Service may execute system calls only with native ABI");
        } else {
                b = 8;
                d = strdup("Service may execute system calls with multiple ABIs");
        }

        if (!d)
                return log_oom();

        *ret_badness = b;
        *ret_description = d;

        return 0;
}

static bool syscall_names_in_filter(Set *s, bool allow_list, const SyscallFilterSet *f, const char **ret_offending_syscall) {
        NULSTR_FOREACH(syscall, f->value) {
                if (syscall[0] == '@') {
                        const SyscallFilterSet *g;

                        assert_se(g = syscall_filter_set_find(syscall));
                        if (syscall_names_in_filter(s, allow_list, g, ret_offending_syscall))
                                return true; /* bad! */

                        continue;
                }

                /* Let's see if the system call actually exists on this platform, before complaining */
                if (seccomp_syscall_resolve_name(syscall) < 0)
                        continue;

                if (set_contains(s, syscall) == allow_list) {
                        log_debug("Offending syscall filter item: %s", syscall);
                        if (ret_offending_syscall)
                                *ret_offending_syscall = syscall;
                        return true; /* bad! */
                }
        }

        *ret_offending_syscall = NULL;
        return false;
}

static int assess_system_call_filter(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(a);
        assert(info);
        assert(ret_badness);
        assert(ret_description);

        assert(a->parameter < _SYSCALL_FILTER_SET_MAX);
        const SyscallFilterSet *f = syscall_filter_sets + a->parameter;

        _cleanup_free_ char *d = NULL;
        uint64_t b;
        int r;

        if (!info->system_call_filter_allow_list && set_isempty(info->system_call_filter)) {
                r = free_and_strdup(&d, "Service does not filter system calls");
                b = 10;
        } else {
                bool bad;
                const char *offender = NULL;

                log_debug("Analyzing system call filter, checking against: %s", f->name);
                bad = syscall_names_in_filter(info->system_call_filter, info->system_call_filter_allow_list, f, &offender);
                log_debug("Result: %s", bad ? "bad" : "good");

                if (info->system_call_filter_allow_list) {
                        if (bad) {
                                r = asprintf(&d, "System call allow list defined for service, and %s is included "
                                             "(e.g. %s is allowed)",
                                             f->name, offender);
                                b = 9;
                        } else {
                                r = asprintf(&d, "System call allow list defined for service, and %s is not included",
                                             f->name);
                                b = 0;
                        }
                } else {
                        if (bad) {
                                r = asprintf(&d, "System call deny list defined for service, and %s is not included "
                                             "(e.g. %s is allowed)",
                                             f->name, offender);
                                b = 10;
                        } else {
                                r = asprintf(&d, "System call deny list defined for service, and %s is included",
                                             f->name);
                                b = 0;
                        }
                }
        }
        if (r < 0)
                return log_oom();

        *ret_badness = b;
        *ret_description = TAKE_PTR(d);

        return 0;
}

#endif

static int assess_ip_address_allow(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        char *d = NULL;
        uint64_t b;

        assert(info);
        assert(ret_badness);
        assert(ret_description);

        if (info->ip_filters_custom_ingress || info->ip_filters_custom_egress) {
                d = strdup("Service defines custom ingress/egress IP filters with BPF programs");
                b = 0;
        } else if (!info->ip_address_deny_all) {
                d = strdup("Service does not define an IP address allow list");
                b = 10;
        } else if (info->ip_address_allow_other) {
                d = strdup("Service defines IP address allow list with non-localhost entries");
                b = 5;
        } else if (info->ip_address_allow_localhost) {
                d = strdup("Service defines IP address allow list with only localhost entries");
                b = 2;
        } else {
                d = strdup("Service blocks all IP address ranges");
                b = 0;
        }

        if (!d)
                return log_oom();

        *ret_badness = b;
        *ret_description = d;

        return 0;
}

static int assess_device_allow(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        char *d = NULL;
        uint64_t b;

        assert(info);
        assert(ret_badness);
        assert(ret_description);

        if (STRPTR_IN_SET(info->device_policy, "strict", "closed")) {

                if (!strv_isempty(info->device_allow)) {
                        _cleanup_free_ char *join = NULL;

                        join = strv_join(info->device_allow, " ");
                        if (!join)
                                return log_oom();

                        d = strjoin("Service has a device ACL with some special devices: ", join);
                        b = 5;
                } else {
                        d = strdup("Service has a minimal device ACL");
                        b = 0;
                }
        } else {
                d = strdup("Service has no device ACL");
                b = 10;
        }

        if (!d)
                return log_oom();

        *ret_badness = b;
        *ret_description = d;

        return 0;
}

static int assess_ambient_capabilities(
                const struct security_assessor *a,
                const SecurityInfo *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness = info->ambient_capabilities != 0;
        *ret_description = NULL;

        return 0;
}

static const struct security_assessor security_assessor_table[] = {
        {
                .id = "User=/DynamicUser=",
                .json_field = "UserOrDynamicUser",
                .description_bad = "Service runs as root user",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#User=",
                .weight = 2000,
                .range = 10,
                .assess = assess_user,
        },
        {
                .id = "SupplementaryGroups=",
                .json_field = "SupplementaryGroups",
                .description_good = "Service has no supplementary groups",
                .description_bad = "Service runs with supplementary groups",
                .description_na = "Service runs as root, option does not matter",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SupplementaryGroups=",
                .weight = 200,
                .range = 1,
                .assess = assess_supplementary_groups,
        },
        {
                .id = "PrivateDevices=",
                .json_field = "PrivateDevices",
                .description_good = "Service has no access to hardware devices",
                .description_bad = "Service potentially has access to hardware devices",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateDevices=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, private_devices),
        },
        {
                .id = "PrivateMounts=",
                .json_field = "PrivateMounts",
                .description_good = "Service cannot install system mounts",
                .description_bad = "Service may install system mounts",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateMounts=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, private_mounts),
        },
        {
                .id = "PrivateNetwork=",
                .json_field = "PrivateNetwork",
                .description_good = "Service has no access to the host's network",
                .description_bad = "Service has access to the host's network",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateNetwork=",
                .weight = 2500,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, private_network),
        },
        {
                .id = "PrivateTmp=",
                .json_field = "PrivateTmp",
                .description_good = "Service has no access to other software's temporary files",
                .description_bad = "Service has access to other software's temporary files",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateTmp=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, private_tmp),
                .default_dependencies_only = true,
        },
        {
                .id = "PrivateUsers=",
                .json_field = "PrivateUsers",
                .description_good = "Service does not have access to other users",
                .description_bad = "Service has access to other users",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateUsers=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, private_users),
        },
        {
                .id = "ProtectControlGroups=",
                .json_field = "ProtectControlGroups",
                .description_good = "Service cannot modify the control group file system",
                .description_bad = "Service may modify the control group file system",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectControlGroups=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, protect_control_groups),
        },
        {
                .id = "ProtectKernelModules=",
                .json_field = "ProtectKernelModules",
                .description_good = "Service cannot load or read kernel modules",
                .description_bad = "Service may load or read kernel modules",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelModules=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, protect_kernel_modules),
        },
        {
                .id = "ProtectKernelTunables=",
                .json_field = "ProtectKernelTunables",
                .description_good = "Service cannot alter kernel tunables (/proc/sys, …)",
                .description_bad = "Service may alter kernel tunables",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelTunables=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, protect_kernel_tunables),
        },
        {
                .id = "ProtectKernelLogs=",
                .json_field = "ProtectKernelLogs",
                .description_good = "Service cannot read from or write to the kernel log ring buffer",
                .description_bad = "Service may read from or write to the kernel log ring buffer",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelLogs=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, protect_kernel_logs),
        },
        {
                .id = "ProtectClock=",
                .json_field = "ProtectClock",
                .description_good = "Service cannot write to the hardware clock or system clock",
                .description_bad = "Service may write to the hardware clock or system clock",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectClock=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, protect_clock),
        },
        {
                .id = "ProtectHome=",
                .json_field = "ProtectHome",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHome=",
                .weight = 1000,
                .range = 10,
                .assess = assess_protect_home,
                .default_dependencies_only = true,
        },
        {
                .id = "ProtectHostname=",
                .json_field = "ProtectHostname",
                .description_good = "Service cannot change system host/domainname",
                .description_bad = "Service may change system host/domainname",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHostname=",
                .weight = 50,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, protect_hostname),
        },
        {
                .id = "ProtectSystem=",
                .json_field = "ProtectSystem",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=",
                .weight = 1000,
                .range = 10,
                .assess = assess_protect_system,
                .default_dependencies_only = true,
        },
        {
                .id = "RootDirectory=/RootImage=",
                .json_field = "RootDirectoryOrRootImage",
                .description_good = "Service has its own root directory/image",
                .description_bad = "Service runs within the host's root directory",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RootDirectory=",
                .weight = 200,
                .range = 1,
                .assess = assess_root_directory,
                .default_dependencies_only = true,
        },
        {
                .id = "LockPersonality=",
                .json_field = "LockPersonality",
                .description_good = "Service cannot change ABI personality",
                .description_bad = "Service may change ABI personality",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#LockPersonality=",
                .weight = 100,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, lock_personality),
        },
        {
                .id = "MemoryDenyWriteExecute=",
                .json_field = "MemoryDenyWriteExecute",
                .description_good = "Service cannot create writable executable memory mappings",
                .description_bad = "Service may create writable executable memory mappings",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#MemoryDenyWriteExecute=",
                .weight = 100,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, memory_deny_write_execute),
        },
        {
                .id = "NoNewPrivileges=",
                .json_field = "NoNewPrivileges",
                .description_good = "Service processes cannot acquire new privileges",
                .description_bad = "Service processes may acquire new privileges",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#NoNewPrivileges=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, no_new_privileges),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_ADMIN",
                .json_field = "CapabilityBoundingSet_CAP_SYS_ADMIN",
                .description_good = "Service has no administrator privileges",
                .description_bad = "Service has administrator privileges",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1500,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = UINT64_C(1) << CAP_SYS_ADMIN,
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SET(UID|GID|PCAP)",
                .json_field = "CapabilityBoundingSet_CAP_SET_UID_GID_PCAP",
                .description_good = "Service cannot change UID/GID identities/capabilities",
                .description_bad = "Service may change UID/GID identities/capabilities",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1500,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SETUID)|
                             (UINT64_C(1) << CAP_SETGID)|
                             (UINT64_C(1) << CAP_SETPCAP),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_PTRACE",
                .json_field = "CapabilityBoundingSet_CAP_SYS_PTRACE",
                .description_good = "Service has no ptrace() debugging abilities",
                .description_bad = "Service has ptrace() debugging abilities",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1500,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYS_PTRACE),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_TIME",
                .json_field = "CapabilityBoundingSet_CAP_SYS_TIME",
                .description_good = "Service processes cannot change the system clock",
                .description_bad = "Service processes may change the system clock",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1000,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = UINT64_C(1) << CAP_SYS_TIME,
        },
        {
                .id = "CapabilityBoundingSet=~CAP_NET_ADMIN",
                .json_field = "CapabilityBoundingSet_CAP_NET_ADMIN",
                .description_good = "Service has no network configuration privileges",
                .description_bad = "Service has network configuration privileges",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1000,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_NET_ADMIN),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_RAWIO",
                .json_field = "CapabilityBoundingSet_CAP_SYS_RAWIO",
                .description_good = "Service has no raw I/O access",
                .description_bad = "Service has raw I/O access",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1000,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYS_RAWIO),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_MODULE",
                .json_field = "CapabilityBoundingSet_CAP_SYS_MODULE",
                .description_good = "Service cannot load kernel modules",
                .description_bad = "Service may load kernel modules",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1000,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYS_MODULE),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_AUDIT_*",
                .json_field = "CapabilityBoundingSet_CAP_AUDIT",
                .description_good = "Service has no audit subsystem access",
                .description_bad = "Service has audit subsystem access",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 500,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_AUDIT_CONTROL) |
                             (UINT64_C(1) << CAP_AUDIT_READ) |
                             (UINT64_C(1) << CAP_AUDIT_WRITE),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYSLOG",
                .json_field = "CapabilityBoundingSet_CAP_SYSLOG",
                .description_good = "Service has no access to kernel logging",
                .description_bad = "Service has access to kernel logging",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 500,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYSLOG),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_(NICE|RESOURCE)",
                .json_field = "CapabilityBoundingSet_CAP_SYS_NICE_RESOURCE",
                .description_good = "Service has no privileges to change resource use parameters",
                .description_bad = "Service has privileges to change resource use parameters",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 500,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYS_NICE) |
                             (UINT64_C(1) << CAP_SYS_RESOURCE),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_MKNOD",
                .json_field = "CapabilityBoundingSet_CAP_MKNOD",
                .description_good = "Service cannot create device nodes",
                .description_bad = "Service may create device nodes",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 500,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_MKNOD),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_(CHOWN|FSETID|SETFCAP)",
                .json_field = "CapabilityBoundingSet_CAP_CHOWN_FSETID_SETFCAP",
                .description_good = "Service cannot change file ownership/access mode/capabilities",
                .description_bad = "Service may change file ownership/access mode/capabilities unrestricted",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1000,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_CHOWN) |
                             (UINT64_C(1) << CAP_FSETID) |
                             (UINT64_C(1) << CAP_SETFCAP),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_(DAC_*|FOWNER|IPC_OWNER)",
                .json_field = "CapabilityBoundingSet_CAP_DAC_FOWNER_IPC_OWNER",
                .description_good = "Service cannot override UNIX file/IPC permission checks",
                .description_bad = "Service may override UNIX file/IPC permission checks",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1000,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_DAC_OVERRIDE) |
                             (UINT64_C(1) << CAP_DAC_READ_SEARCH) |
                             (UINT64_C(1) << CAP_FOWNER) |
                             (UINT64_C(1) << CAP_IPC_OWNER),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_KILL",
                .json_field = "CapabilityBoundingSet_CAP_KILL",
                .description_good = "Service cannot send UNIX signals to arbitrary processes",
                .description_bad = "Service may send UNIX signals to arbitrary processes",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 500,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_KILL),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_NET_(BIND_SERVICE|BROADCAST|RAW)",
                .json_field = "CapabilityBoundingSet_CAP_NET_BIND_SERVICE_BROADCAST_RAW)",
                .description_good = "Service has no elevated networking privileges",
                .description_bad = "Service has elevated networking privileges",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 500,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_NET_BIND_SERVICE) |
                             (UINT64_C(1) << CAP_NET_BROADCAST) |
                             (UINT64_C(1) << CAP_NET_RAW),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_BOOT",
                .json_field = "CapabilityBoundingSet_CAP_SYS_BOOT",
                .description_good = "Service cannot issue reboot()",
                .description_bad = "Service may issue reboot()",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 100,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYS_BOOT),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_MAC_*",
                .json_field = "CapabilityBoundingSet_CAP_MAC",
                .description_good = "Service cannot adjust SMACK MAC",
                .description_bad = "Service may adjust SMACK MAC",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 100,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_MAC_ADMIN)|
                             (UINT64_C(1) << CAP_MAC_OVERRIDE),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_LINUX_IMMUTABLE",
                .json_field = "CapabilityBoundingSet_CAP_LINUX_IMMUTABLE",
                .description_good = "Service cannot mark files immutable",
                .description_bad = "Service may mark files immutable",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 75,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_LINUX_IMMUTABLE),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_IPC_LOCK",
                .json_field = "CapabilityBoundingSet_CAP_IPC_LOCK",
                .description_good = "Service cannot lock memory into RAM",
                .description_bad = "Service may lock memory into RAM",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 50,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_IPC_LOCK),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_CHROOT",
                .json_field = "CapabilityBoundingSet_CAP_SYS_CHROOT",
                .description_good = "Service cannot issue chroot()",
                .description_bad = "Service may issue chroot()",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 50,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYS_CHROOT),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_BLOCK_SUSPEND",
                .json_field = "CapabilityBoundingSet_CAP_BLOCK_SUSPEND",
                .description_good = "Service cannot establish wake locks",
                .description_bad = "Service may establish wake locks",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 25,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_BLOCK_SUSPEND),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_WAKE_ALARM",
                .json_field = "CapabilityBoundingSet_CAP_WAKE_ALARM",
                .description_good = "Service cannot program timers that wake up the system",
                .description_bad = "Service may program timers that wake up the system",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 25,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_WAKE_ALARM),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_LEASE",
                .json_field = "CapabilityBoundingSet_CAP_LEASE",
                .description_good = "Service cannot create file leases",
                .description_bad = "Service may create file leases",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 25,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_LEASE),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_TTY_CONFIG",
                .json_field = "CapabilityBoundingSet_CAP_SYS_TTY_CONFIG",
                .description_good = "Service cannot issue vhangup()",
                .description_bad = "Service may issue vhangup()",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 25,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYS_TTY_CONFIG),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_PACCT",
                .json_field = "CapabilityBoundingSet_CAP_SYS_PACCT",
                .description_good = "Service cannot use acct()",
                .description_bad = "Service may use acct()",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 25,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYS_PACCT),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_BPF",
                .json_field = "CapabilityBoundingSet_CAP_BPF",
                .description_good = "Service may load BPF programs",
                .description_bad = "Service may not load BPF programs",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 25,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_BPF),
        },
        {
                .id = "UMask=",
                .json_field = "UMask",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#UMask=",
                .weight = 100,
                .range = 10,
                .assess = assess_umask,
        },
        {
                .id = "KeyringMode=",
                .json_field = "KeyringMode",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#KeyringMode=",
                .description_good = "Service doesn't share key material with other services",
                .description_bad = "Service shares key material with other service",
                .weight = 1000,
                .range = 1,
                .assess = assess_keyring_mode,
        },
        {
                .id = "ProtectProc=",
                .json_field = "ProtectProc",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectProc=",
                .description_good = "Service has restricted access to process tree (/proc hidepid=)",
                .description_bad = "Service has full access to process tree (/proc hidepid=)",
                .weight = 1000,
                .range = 3,
                .assess = assess_protect_proc,
        },
        {
                .id = "ProcSubset=",
                .json_field = "ProcSubset",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProcSubset=",
                .description_good = "Service has no access to non-process /proc files (/proc subset=)",
                .description_bad = "Service has full access to non-process /proc files (/proc subset=)",
                .weight = 10,
                .range = 1,
                .assess = assess_proc_subset,
        },
        {
                .id = "NotifyAccess=",
                .json_field = "NotifyAccess",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#NotifyAccess=",
                .description_good = "Service child processes cannot alter service state",
                .description_bad = "Service child processes may alter service state",
                .weight = 1000,
                .range = 1,
                .assess = assess_notify_access,
        },
        {
                .id = "RemoveIPC=",
                .json_field = "RemoveIPC",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RemoveIPC=",
                .description_good = "Service user cannot leave SysV IPC objects around",
                .description_bad = "Service user may leave SysV IPC objects around",
                .description_na = "Service runs as root, option does not apply",
                .weight = 100,
                .range = 1,
                .assess = assess_remove_ipc,
                .offset = offsetof(SecurityInfo, remove_ipc),
        },
        {
                .id = "Delegate=",
                .json_field = "Delegate",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Delegate=",
                .description_good = "Service does not maintain its own delegated control group subtree",
                .description_bad = "Service maintains its own delegated control group subtree",
                .weight = 100,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, delegate),
                .parameter = true, /* invert! */
        },
        {
                .id = "RestrictRealtime=",
                .json_field = "RestrictRealtime",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictRealtime=",
                .description_good = "Service realtime scheduling access is restricted",
                .description_bad = "Service may acquire realtime scheduling",
                .weight = 500,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, restrict_realtime),
        },
        {
                .id = "RestrictSUIDSGID=",
                .json_field = "RestrictSUIDSGID",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictSUIDSGID=",
                .description_good = "SUID/SGID file creation by service is restricted",
                .description_bad = "Service may create SUID/SGID files",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, restrict_suid_sgid),
        },
        {
                .id = "RestrictNamespaces=~user",
                .json_field = "RestrictNamespaces_user",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create user namespaces",
                .description_bad = "Service may create user namespaces",
                .weight = 1500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWUSER,
        },
        {
                .id = "RestrictNamespaces=~mnt",
                .json_field = "RestrictNamespaces_mnt",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create file system namespaces",
                .description_bad = "Service may create file system namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWNS,
        },
        {
                .id = "RestrictNamespaces=~ipc",
                .json_field = "RestrictNamespaces_ipc",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create IPC namespaces",
                .description_bad = "Service may create IPC namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWIPC,
        },
        {
                .id = "RestrictNamespaces=~pid",
                .json_field = "RestrictNamespaces_pid",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create process namespaces",
                .description_bad = "Service may create process namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWPID,
        },
        {
                .id = "RestrictNamespaces=~cgroup",
                .json_field = "RestrictNamespaces_cgroup",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create cgroup namespaces",
                .description_bad = "Service may create cgroup namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWCGROUP,
        },
        {
                .id = "RestrictNamespaces=~net",
                .json_field = "RestrictNamespaces_net",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create network namespaces",
                .description_bad = "Service may create network namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWNET,
        },
        {
                .id = "RestrictNamespaces=~uts",
                .json_field = "RestrictNamespaces_uts",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create hostname namespaces",
                .description_bad = "Service may create hostname namespaces",
                .weight = 100,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWUTS,
        },
        {
                .id = "RestrictAddressFamilies=~AF_(INET|INET6)",
                .json_field = "RestrictAddressFamilies_AF_INET_INET6",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate Internet sockets",
                .description_bad = "Service may allocate Internet sockets",
                .weight = 1500,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, restrict_address_family_inet),
        },
        {
                .id = "RestrictAddressFamilies=~AF_UNIX",
                .json_field = "RestrictAddressFamilies_AF_UNIX",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate local sockets",
                .description_bad = "Service may allocate local sockets",
                .weight = 25,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, restrict_address_family_unix),
        },
        {
                .id = "RestrictAddressFamilies=~AF_NETLINK",
                .json_field = "RestrictAddressFamilies_AF_NETLINK",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate netlink sockets",
                .description_bad = "Service may allocate netlink sockets",
                .weight = 200,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, restrict_address_family_netlink),
        },
        {
                .id = "RestrictAddressFamilies=~AF_PACKET",
                .json_field = "RestrictAddressFamilies_AF_PACKET",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate packet sockets",
                .description_bad = "Service may allocate packet sockets",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, restrict_address_family_packet),
        },
        {
                .id = "RestrictAddressFamilies=~…",
                .json_field = "RestrictAddressFamilies_OTHER",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate exotic sockets",
                .description_bad = "Service may allocate exotic sockets",
                .weight = 1250,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(SecurityInfo, restrict_address_family_other),
        },
#if HAVE_SECCOMP
        {
                .id = "SystemCallArchitectures=",
                .json_field = "SystemCallArchitectures",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallArchitectures=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_architectures,
        },
        {
                .id = "SystemCallFilter=~@swap",
                .json_field = "SystemCallFilter_swap",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_SWAP,
        },
        {
                .id = "SystemCallFilter=~@obsolete",
                .json_field = "SystemCallFilter_obsolete",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 250,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_OBSOLETE,
        },
        {
                .id = "SystemCallFilter=~@clock",
                .json_field = "SystemCallFilter_clock",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_CLOCK,
        },
        {
                .id = "SystemCallFilter=~@cpu-emulation",
                .json_field = "SystemCallFilter_cpu_emulation",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 250,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_CPU_EMULATION,
        },
        {
                .id = "SystemCallFilter=~@debug",
                .json_field = "SystemCallFilter_debug",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_DEBUG,
        },
        {
                .id = "SystemCallFilter=~@mount",
                .json_field = "SystemCallFilter_mount",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_MOUNT,
        },
        {
                .id = "SystemCallFilter=~@module",
                .json_field = "SystemCallFilter_module",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_MODULE,
        },
        {
                .id = "SystemCallFilter=~@raw-io",
                .json_field = "SystemCallFilter_raw_io",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_RAW_IO,
        },
        {
                .id = "SystemCallFilter=~@reboot",
                .json_field = "SystemCallFilter_reboot",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_REBOOT,
        },
        {
                .id = "SystemCallFilter=~@privileged",
                .json_field = "SystemCallFilter_privileged",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 700,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_PRIVILEGED,
        },
        {
                .id = "SystemCallFilter=~@resources",
                .json_field = "SystemCallFilter_resources",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 700,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_RESOURCES,
        },
#endif
        {
                .id = "IPAddressDeny=",
                .json_field = "IPAddressDeny",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#IPAddressDeny=",
                .weight = 1000,
                .range = 10,
                .assess = assess_ip_address_allow,
        },
        {
                .id = "DeviceAllow=",
                .json_field = "DeviceAllow",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#DeviceAllow=",
                .weight = 1000,
                .range = 10,
                .assess = assess_device_allow,
        },
        {
                .id = "AmbientCapabilities=",
                .json_field = "AmbientCapabilities",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#AmbientCapabilities=",
                .description_good = "Service process does not receive ambient capabilities",
                .description_bad = "Service process receives ambient capabilities",
                .weight = 500,
                .range = 1,
                .assess = assess_ambient_capabilities,
        },
};

static JsonVariant* security_assessor_find_in_policy(const struct security_assessor *a, JsonVariant *policy, const char *name) {
        JsonVariant *item;
        assert(a);

        if (!policy)
                return NULL;
        if (!json_variant_is_object(policy)) {
                log_debug("Specified policy is not a JSON object, ignoring.");
                return NULL;
        }

        item = json_variant_by_key(policy, a->json_field);
        if (!item)
                return NULL;
        if (!json_variant_is_object(item)) {
                log_debug("Item for '%s' in policy JSON object is not an object, ignoring.", a->id);
                return NULL;
        }

        return name ? json_variant_by_key(item, name) : item;
}

static uint64_t access_weight(const struct security_assessor *a, JsonVariant *policy) {
        JsonVariant *val;

        assert(a);

        val = security_assessor_find_in_policy(a, policy, "weight");
        if (val) {
                if (json_variant_is_unsigned(val))
                        return json_variant_unsigned(val);
                log_debug("JSON field 'weight' of policy for %s is not an unsigned integer, ignoring.", a->id);
        }

        return a->weight;
}

static uint64_t access_range(const struct security_assessor *a, JsonVariant *policy) {
        JsonVariant *val;

        assert(a);

        val = security_assessor_find_in_policy(a, policy, "range");
        if (val) {
                if (json_variant_is_unsigned(val))
                        return json_variant_unsigned(val);
                log_debug("JSON field 'range' of policy for %s is not an unsigned integer, ignoring.", a->id);
        }

        return a->range;
}

static const char *access_description_na(const struct security_assessor *a, JsonVariant *policy) {
        JsonVariant *val;

        assert(a);

        val = security_assessor_find_in_policy(a, policy, "description_na");
        if (val) {
                if (json_variant_is_string(val))
                        return json_variant_string(val);
                log_debug("JSON field 'description_na' of policy for %s is not a string, ignoring.", a->id);
        }

        return a->description_na;
}

static const char *access_description_good(const struct security_assessor *a, JsonVariant *policy) {
        JsonVariant *val;

        assert(a);

        val = security_assessor_find_in_policy(a, policy, "description_good");
        if (val) {
                if (json_variant_is_string(val))
                        return json_variant_string(val);
                log_debug("JSON field 'description_good' of policy for %s is not a string, ignoring.", a->id);
        }

        return a->description_good;
}

static const char *access_description_bad(const struct security_assessor *a, JsonVariant *policy) {
        JsonVariant *val;

        assert(a);

        val = security_assessor_find_in_policy(a, policy, "description_bad");
        if (val) {
                if (json_variant_is_string(val))
                        return json_variant_string(val);
                log_debug("JSON field 'description_bad' of policy for %s is not a string, ignoring.", a->id);
        }

        return a->description_bad;
}

static int assess(const SecurityInfo *info,
                  Table *overview_table,
                  AnalyzeSecurityFlags flags,
                  unsigned threshold,
                  JsonVariant *policy,
                  PagerFlags pager_flags,
                  JsonFormatFlags json_format_flags) {

        static const struct {
                uint64_t exposure;
                const char *name;
                const char *color;
                SpecialGlyph smiley;
        } badness_table[] = {
                { 100, "DANGEROUS", ANSI_HIGHLIGHT_RED,    SPECIAL_GLYPH_DEPRESSED_SMILEY        },
                { 90,  "UNSAFE",    ANSI_HIGHLIGHT_RED,    SPECIAL_GLYPH_UNHAPPY_SMILEY          },
                { 75,  "EXPOSED",   ANSI_HIGHLIGHT_YELLOW, SPECIAL_GLYPH_SLIGHTLY_UNHAPPY_SMILEY },
                { 50,  "MEDIUM",    NULL,                  SPECIAL_GLYPH_NEUTRAL_SMILEY          },
                { 10,  "OK",        ANSI_HIGHLIGHT_GREEN,  SPECIAL_GLYPH_SLIGHTLY_HAPPY_SMILEY   },
                { 1,   "SAFE",      ANSI_HIGHLIGHT_GREEN,  SPECIAL_GLYPH_HAPPY_SMILEY            },
                { 0,   "PERFECT",   ANSI_HIGHLIGHT_GREEN,  SPECIAL_GLYPH_ECSTATIC_SMILEY         },
        };

        uint64_t badness_sum = 0, weight_sum = 0, exposure;
        _cleanup_(table_unrefp) Table *details_table = NULL;
        size_t i;
        int r;

        if (!FLAGS_SET(flags, ANALYZE_SECURITY_SHORT)) {
                details_table = table_new(" ", "name", "json_field", "description", "weight", "badness", "range", "exposure");
                if (!details_table)
                        return log_oom();

                r = table_set_json_field_name(details_table, 0, "set");
                if (r < 0)
                        return log_error_errno(r, "Failed to set JSON field name of column 0: %m");

                (void) table_set_sort(details_table, (size_t) 3, (size_t) 1);
                (void) table_set_reverse(details_table, 3, true);

                if (getenv_bool("SYSTEMD_ANALYZE_DEBUG") <= 0)
                        (void) table_set_display(details_table, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3, (size_t) 7);
        }

        for (i = 0; i < ELEMENTSOF(security_assessor_table); i++) {
                const struct security_assessor *a = security_assessor_table + i;
                _cleanup_free_ char *d = NULL;
                uint64_t badness;
                void *data;
                uint64_t weight = access_weight(a, policy);
                uint64_t range = access_range(a, policy);

                data = (uint8_t *) info + a->offset;

                if (a->default_dependencies_only && !info->default_dependencies) {
                        badness = UINT64_MAX;
                        d = strdup("Service runs in special boot phase, option is not appropriate");
                        if (!d)
                                return log_oom();
                } else if (weight == 0) {
                        badness = UINT64_MAX;
                        d = strdup("Option excluded by policy, skipping");
                        if (!d)
                                return log_oom();
                } else {
                        r = a->assess(a, info, data, &badness, &d);
                        if (r < 0)
                                return r;
                }

                assert(range > 0);

                if (badness != UINT64_MAX) {
                        assert(badness <= range);

                        badness_sum += DIV_ROUND_UP(badness * weight, range);
                        weight_sum += weight;
                }

                if (details_table) {
                        const char *description, *color = NULL;
                        int checkmark;

                        if (badness == UINT64_MAX) {
                                checkmark = -1;
                                description = access_description_na(a, policy);
                                color = NULL;
                        } else if (badness == a->range) {
                                checkmark = 0;
                                description = access_description_bad(a, policy);
                                color = ansi_highlight_red();
                        } else if (badness == 0) {
                                checkmark = 1;
                                description = access_description_good(a, policy);
                                color = ansi_highlight_green();
                        } else {
                                checkmark = 0;
                                description = NULL;
                                color = ansi_highlight_red();
                        }

                        if (d)
                                description = d;

                        if (checkmark < 0) {
                                r = table_add_many(details_table, TABLE_EMPTY);
                                if (r < 0)
                                        return table_log_add_error(r);
                        } else {
                                r = table_add_many(details_table,
                                                   TABLE_BOOLEAN_CHECKMARK, checkmark > 0,
                                                   TABLE_SET_MINIMUM_WIDTH, 1,
                                                   TABLE_SET_MAXIMUM_WIDTH, 1,
                                                   TABLE_SET_ELLIPSIZE_PERCENT, 0,
                                                   TABLE_SET_COLOR, color);
                                if (r < 0)
                                        return table_log_add_error(r);
                        }

                        r = table_add_many(details_table,
                                           TABLE_STRING, a->id, TABLE_SET_URL, a->url,
                                           TABLE_STRING, a->json_field,
                                           TABLE_STRING, description,
                                           TABLE_UINT64, weight, TABLE_SET_ALIGN_PERCENT, 100,
                                           TABLE_UINT64, badness, TABLE_SET_ALIGN_PERCENT, 100,
                                           TABLE_UINT64, range, TABLE_SET_ALIGN_PERCENT, 100,
                                           TABLE_EMPTY, TABLE_SET_ALIGN_PERCENT, 100);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        assert(weight_sum > 0);

        if (details_table) {
                size_t row;

                for (row = 1; row < table_get_rows(details_table); row++) {
                        char buf[DECIMAL_STR_MAX(uint64_t) + 1 + DECIMAL_STR_MAX(uint64_t) + 1];
                        const uint64_t *weight, *badness, *range;
                        TableCell *cell;
                        uint64_t x;

                        assert_se(weight = table_get_at(details_table, row, 4));
                        assert_se(badness = table_get_at(details_table, row, 5));
                        assert_se(range = table_get_at(details_table, row, 6));

                        if (*badness == UINT64_MAX || *badness == 0)
                                continue;

                        assert_se(cell = table_get_cell(details_table, row, 7));

                        x = DIV_ROUND_UP(DIV_ROUND_UP(*badness * *weight * 100U, *range), weight_sum);
                        xsprintf(buf, "%" PRIu64 ".%" PRIu64, x / 10, x % 10);

                        r = table_update(details_table, cell, TABLE_STRING, buf);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update cell in table: %m");
                }

                if (json_format_flags & JSON_FORMAT_OFF) {
                        r = table_hide_column_from_display(details_table, (size_t) 2);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set columns to display: %m");
                }

                r = table_print_with_pager(details_table, json_format_flags, pager_flags, /* show_header= */true);
                if (r < 0)
                        return log_error_errno(r, "Failed to output table: %m");
        }

        exposure = DIV_ROUND_UP(badness_sum * 100U, weight_sum);

        for (i = 0; i < ELEMENTSOF(badness_table); i++)
                if (exposure >= badness_table[i].exposure)
                        break;

        assert(i < ELEMENTSOF(badness_table));

        if (details_table && (json_format_flags & JSON_FORMAT_OFF)) {
                _cleanup_free_ char *clickable = NULL;
                const char *name;

                /* If we shall output the details table, also print the brief summary underneath */

                if (info->fragment_path) {
                        r = terminal_urlify_path(info->fragment_path, info->id, &clickable);
                        if (r < 0)
                                return log_oom();

                        name = clickable;
                } else
                        name = info->id;

                printf("\n%s %sOverall exposure level for %s%s: %s%" PRIu64 ".%" PRIu64 " %s%s %s\n",
                       special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                       ansi_highlight(),
                       name,
                       ansi_normal(),
                       colors_enabled() ? strempty(badness_table[i].color) : "",
                       exposure / 10, exposure % 10,
                       badness_table[i].name,
                       ansi_normal(),
                       special_glyph(badness_table[i].smiley));
        }

        fflush(stdout);

        if (overview_table) {
                char buf[DECIMAL_STR_MAX(uint64_t) + 1 + DECIMAL_STR_MAX(uint64_t) + 1];
                _cleanup_free_ char *url = NULL;

                if (info->fragment_path) {
                        r = file_url_from_path(info->fragment_path, &url);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate URL from path: %m");
                }

                xsprintf(buf, "%" PRIu64 ".%" PRIu64, exposure / 10, exposure % 10);

                r = table_add_many(overview_table,
                                   TABLE_STRING, info->id,
                                   TABLE_SET_URL, url,
                                   TABLE_STRING, buf,
                                   TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_STRING, badness_table[i].name,
                                   TABLE_SET_COLOR, strempty(badness_table[i].color),
                                   TABLE_STRING, special_glyph(badness_table[i].smiley));
                if (r < 0)
                        return table_log_add_error(r);
        }

        /* Return error when overall exposure level is over threshold */
        if (exposure > threshold)
                return -EINVAL;

        return 0;
}

static int property_read_restrict_namespaces(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        SecurityInfo *info = ASSERT_PTR(userdata);
        int r;
        uint64_t namespaces;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_read(m, "t", &namespaces);
        if (r < 0)
                return r;

        info->restrict_namespaces = (unsigned long long) namespaces;

        return 0;
}

static int property_read_umask(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        SecurityInfo *info = ASSERT_PTR(userdata);
        int r;
        uint32_t umask;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_read(m, "u", &umask);
        if (r < 0)
                return r;

        info->_umask = (mode_t) umask;

        return 0;
}

static int property_read_restrict_address_families(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        SecurityInfo *info = userdata;
        int allow_list, r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'r', "bas");
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "b", &allow_list);
        if (r < 0)
                return r;

        info->restrict_address_family_inet =
                info->restrict_address_family_unix =
                info->restrict_address_family_netlink =
                info->restrict_address_family_packet =
                info->restrict_address_family_other = allow_list;

        r = sd_bus_message_enter_container(m, 'a', "s");
        if (r < 0)
                return r;

        for (;;) {
                const char *name;

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (STR_IN_SET(name, "AF_INET", "AF_INET6"))
                        info->restrict_address_family_inet = !allow_list;
                else if (streq(name, "AF_UNIX"))
                        info->restrict_address_family_unix = !allow_list;
                else if (streq(name, "AF_NETLINK"))
                        info->restrict_address_family_netlink = !allow_list;
                else if (streq(name, "AF_PACKET"))
                        info->restrict_address_family_packet = !allow_list;
                else
                        info->restrict_address_family_other = !allow_list;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return sd_bus_message_exit_container(m);
}

static int property_read_syscall_archs(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        SecurityInfo *info = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'a', "s");
        if (r < 0)
                return r;

        for (;;) {
                const char *name;

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = set_put_strdup(&info->system_call_architectures, name);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_exit_container(m);
}

static int property_read_system_call_filter(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        SecurityInfo *info = userdata;
        int allow_list, r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'r', "bas");
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "b", &allow_list);
        if (r < 0)
                return r;

        info->system_call_filter_allow_list = allow_list;

        r = sd_bus_message_enter_container(m, 'a', "s");
        if (r < 0)
                return r;

        for (;;) {
                const char *name;

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* ignore errno or action after colon */
                r = set_put_strndup(&info->system_call_filter, name, strchrnul(name, ':') - name);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return sd_bus_message_exit_container(m);
}

static int property_read_ip_address_allow(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        SecurityInfo *info = userdata;
        bool deny_ipv4 = false, deny_ipv6 = false;
        int r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'a', "(iayu)");
        if (r < 0)
                return r;

        for (;;) {
                const void *data;
                size_t size;
                int32_t family;
                uint32_t prefixlen;

                r = sd_bus_message_enter_container(m, 'r', "iayu");
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = sd_bus_message_read(m, "i", &family);
                if (r < 0)
                        return r;

                r = sd_bus_message_read_array(m, 'y', &data, &size);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(m, "u", &prefixlen);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;

                if (streq(member, "IPAddressAllow")) {
                        union in_addr_union u;

                        if (family == AF_INET && size == 4 && prefixlen == 8)
                                memcpy(&u.in, data, size);
                        else if (family == AF_INET6 && size == 16 && prefixlen == 128)
                                memcpy(&u.in6, data, size);
                        else {
                                info->ip_address_allow_other = true;
                                continue;
                        }

                        if (in_addr_is_localhost(family, &u))
                                info->ip_address_allow_localhost = true;
                        else
                                info->ip_address_allow_other = true;
                } else {
                        assert(streq(member, "IPAddressDeny"));

                        if (family == AF_INET && size == 4 && prefixlen == 0)
                                deny_ipv4 = true;
                        else if (family == AF_INET6 && size == 16 && prefixlen == 0)
                                deny_ipv6 = true;
                }
        }

        info->ip_address_deny_all = deny_ipv4 && deny_ipv6;

        return sd_bus_message_exit_container(m);
}

static int property_read_ip_filters(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        SecurityInfo *info = userdata;
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_read_strv(m, &l);
        if (r < 0)
                return r;

        if (streq(member, "IPIngressFilterPath"))
                info->ip_filters_custom_ingress = !strv_isempty(l);
        else if (streq(member, "IPEgressFilterPath"))
                info->ip_filters_custom_egress = !strv_isempty(l);

        return 0;
}

static int property_read_device_allow(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        SecurityInfo *info = userdata;
        int r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'a', "(ss)");
        if (r < 0)
                return r;

        for (;;) {
                const char *name, *policy;

                r = sd_bus_message_read(m, "(ss)", &name, &policy);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = strv_extendf(&info->device_allow, "%s:%s", name, policy);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_exit_container(m);
}

static int acquire_security_info(sd_bus *bus, const char *name, SecurityInfo *info, AnalyzeSecurityFlags flags) {

        static const struct bus_properties_map security_map[] = {
                { "AmbientCapabilities",     "t",       NULL,                                    offsetof(SecurityInfo, ambient_capabilities)      },
                { "CapabilityBoundingSet",   "t",       NULL,                                    offsetof(SecurityInfo, capability_bounding_set)   },
                { "DefaultDependencies",     "b",       NULL,                                    offsetof(SecurityInfo, default_dependencies)      },
                { "Delegate",                "b",       NULL,                                    offsetof(SecurityInfo, delegate)                  },
                { "DeviceAllow",             "a(ss)",   property_read_device_allow,              0                                                 },
                { "DevicePolicy",            "s",       NULL,                                    offsetof(SecurityInfo, device_policy)             },
                { "DynamicUser",             "b",       NULL,                                    offsetof(SecurityInfo, dynamic_user)              },
                { "FragmentPath",            "s",       NULL,                                    offsetof(SecurityInfo, fragment_path)             },
                { "IPAddressAllow",          "a(iayu)", property_read_ip_address_allow,          0                                                 },
                { "IPAddressDeny",           "a(iayu)", property_read_ip_address_allow,          0                                                 },
                { "IPIngressFilterPath",     "as",      property_read_ip_filters,                0                                                 },
                { "IPEgressFilterPath",      "as",      property_read_ip_filters,                0                                                 },
                { "Id",                      "s",       NULL,                                    offsetof(SecurityInfo, id)                        },
                { "KeyringMode",             "s",       NULL,                                    offsetof(SecurityInfo, keyring_mode)              },
                { "ProtectProc",             "s",       NULL,                                    offsetof(SecurityInfo, protect_proc)              },
                { "ProcSubset",              "s",       NULL,                                    offsetof(SecurityInfo, proc_subset)               },
                { "LoadState",               "s",       NULL,                                    offsetof(SecurityInfo, load_state)                },
                { "LockPersonality",         "b",       NULL,                                    offsetof(SecurityInfo, lock_personality)          },
                { "MemoryDenyWriteExecute",  "b",       NULL,                                    offsetof(SecurityInfo, memory_deny_write_execute) },
                { "NoNewPrivileges",         "b",       NULL,                                    offsetof(SecurityInfo, no_new_privileges)         },
                { "NotifyAccess",            "s",       NULL,                                    offsetof(SecurityInfo, notify_access)             },
                { "PrivateDevices",          "b",       NULL,                                    offsetof(SecurityInfo, private_devices)           },
                { "PrivateMounts",           "b",       NULL,                                    offsetof(SecurityInfo, private_mounts)            },
                { "PrivateNetwork",          "b",       NULL,                                    offsetof(SecurityInfo, private_network)           },
                { "PrivateTmp",              "b",       NULL,                                    offsetof(SecurityInfo, private_tmp)               },
                { "PrivateUsers",            "b",       NULL,                                    offsetof(SecurityInfo, private_users)             },
                { "ProtectControlGroups",    "b",       NULL,                                    offsetof(SecurityInfo, protect_control_groups)    },
                { "ProtectHome",             "s",       NULL,                                    offsetof(SecurityInfo, protect_home)              },
                { "ProtectHostname",         "b",       NULL,                                    offsetof(SecurityInfo, protect_hostname)          },
                { "ProtectKernelModules",    "b",       NULL,                                    offsetof(SecurityInfo, protect_kernel_modules)    },
                { "ProtectKernelTunables",   "b",       NULL,                                    offsetof(SecurityInfo, protect_kernel_tunables)   },
                { "ProtectKernelLogs",       "b",       NULL,                                    offsetof(SecurityInfo, protect_kernel_logs)       },
                { "ProtectClock",            "b",       NULL,                                    offsetof(SecurityInfo, protect_clock)             },
                { "ProtectSystem",           "s",       NULL,                                    offsetof(SecurityInfo, protect_system)            },
                { "RemoveIPC",               "b",       NULL,                                    offsetof(SecurityInfo, remove_ipc)                },
                { "RestrictAddressFamilies", "(bas)",   property_read_restrict_address_families, 0                                                 },
                { "RestrictNamespaces",      "t",       property_read_restrict_namespaces,       0                                                 },
                { "RestrictRealtime",        "b",       NULL,                                    offsetof(SecurityInfo, restrict_realtime)         },
                { "RestrictSUIDSGID",        "b",       NULL,                                    offsetof(SecurityInfo, restrict_suid_sgid)        },
                { "RootDirectory",           "s",       NULL,                                    offsetof(SecurityInfo, root_directory)            },
                { "RootImage",               "s",       NULL,                                    offsetof(SecurityInfo, root_image)                },
                { "SupplementaryGroups",     "as",      NULL,                                    offsetof(SecurityInfo, supplementary_groups)      },
                { "SystemCallArchitectures", "as",      property_read_syscall_archs,             0                                                 },
                { "SystemCallFilter",        "(as)",    property_read_system_call_filter,        0                                                 },
                { "Type",                    "s",       NULL,                                    offsetof(SecurityInfo, type)                      },
                { "UMask",                   "u",       property_read_umask,                     0                                                 },
                { "User",                    "s",       NULL,                                    offsetof(SecurityInfo, user)                      },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        /* Note: this mangles *info on failure! */

        assert(bus);
        assert(name);
        assert(info);

        path = unit_dbus_path_from_name(name);
        if (!path)
                return log_oom();

        r = bus_map_all_properties(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        security_map,
                        BUS_MAP_STRDUP | BUS_MAP_BOOLEAN_AS_BOOL,
                        &error,
                        NULL,
                        info);
        if (r < 0)
                return log_error_errno(r, "Failed to get unit properties: %s", bus_error_message(&error, r));

        if (!streq_ptr(info->load_state, "loaded")) {

                if (FLAGS_SET(flags, ANALYZE_SECURITY_ONLY_LOADED))
                        return -EMEDIUMTYPE;

                if (streq_ptr(info->load_state, "not-found"))
                        log_error("Unit %s not found, cannot analyze.", name);
                else if (streq_ptr(info->load_state, "masked"))
                        log_error("Unit %s is masked, cannot analyze.", name);
                else
                        log_error("Unit %s not loaded properly, cannot analyze.", name);

                return -EINVAL;
        }

        if (FLAGS_SET(flags, ANALYZE_SECURITY_ONLY_LONG_RUNNING) && streq_ptr(info->type, "oneshot"))
                return -EMEDIUMTYPE;

        if (info->private_devices ||
            info->private_tmp ||
            info->protect_control_groups ||
            info->protect_kernel_tunables ||
            info->protect_kernel_modules ||
            !streq_ptr(info->protect_home, "no") ||
            !streq_ptr(info->protect_system, "no") ||
            info->root_image)
                info->private_mounts = true;

        if (info->protect_kernel_modules)
                info->capability_bounding_set &= ~(UINT64_C(1) << CAP_SYS_MODULE);

        if (info->protect_kernel_logs)
                info->capability_bounding_set &= ~(UINT64_C(1) << CAP_SYSLOG);

        if (info->protect_clock)
                info->capability_bounding_set &= ~((UINT64_C(1) << CAP_SYS_TIME) |
                                                   (UINT64_C(1) << CAP_WAKE_ALARM));

        if (info->private_devices)
                info->capability_bounding_set &= ~((UINT64_C(1) << CAP_MKNOD) |
                                                   (UINT64_C(1) << CAP_SYS_RAWIO));

        return 0;
}

static int analyze_security_one(sd_bus *bus,
                                const char *name,
                                Table *overview_table,
                                AnalyzeSecurityFlags flags,
                                unsigned threshold,
                                JsonVariant *policy,
                                PagerFlags pager_flags,
                                JsonFormatFlags json_format_flags) {

        _cleanup_(security_info_freep) SecurityInfo *info = security_info_new();
        if (!info)
                return log_oom();

        int r;

        assert(bus);
        assert(name);

        r = acquire_security_info(bus, name, info, flags);
        if (r == -EMEDIUMTYPE) /* Ignore this one because not loaded or Type is oneshot */
                return 0;
        if (r < 0)
                return r;

        r = assess(info, overview_table, flags, threshold, policy, pager_flags, json_format_flags);
        if (r < 0)
                return r;

        return 0;
}

/* Refactoring SecurityInfo so that it can make use of existing struct variables instead of reading from dbus */
static int get_security_info(Unit *u, ExecContext *c, CGroupContext *g, SecurityInfo **ret_info) {
        assert(ret_info);

        _cleanup_(security_info_freep) SecurityInfo *info = security_info_new();
        if (!info)
                return log_oom();

        if (u) {
                if (u->id) {
                        info->id = strdup(u->id);
                        if (!info->id)
                                return log_oom();
                }
                if (unit_type_to_string(u->type)) {
                        info->type = strdup(unit_type_to_string(u->type));
                        if (!info->type)
                                return log_oom();
                }
                if (unit_load_state_to_string(u->load_state)) {
                        info->load_state = strdup(unit_load_state_to_string(u->load_state));
                        if (!info->load_state)
                                return log_oom();
                }
                if (u->fragment_path) {
                        info->fragment_path = strdup(u->fragment_path);
                        if (!info->fragment_path)
                                return log_oom();
                }
                info->default_dependencies = u->default_dependencies;
                if (u->type == UNIT_SERVICE && notify_access_to_string(SERVICE(u)->notify_access)) {
                        info->notify_access = strdup(notify_access_to_string(SERVICE(u)->notify_access));
                        if (!info->notify_access)
                                return log_oom();
                }
        }

        if (c) {
                info->ambient_capabilities = c->capability_ambient_set;
                info->capability_bounding_set = c->capability_bounding_set;
                if (c->user) {
                        info->user = strdup(c->user);
                        if (!info->user)
                                return log_oom();
                }
                if (c->supplementary_groups) {
                        info->supplementary_groups = strv_copy(c->supplementary_groups);
                        if (!info->supplementary_groups)
                                return log_oom();
                }
                info->dynamic_user = c->dynamic_user;
                if (exec_keyring_mode_to_string(c->keyring_mode)) {
                        info->keyring_mode = strdup(exec_keyring_mode_to_string(c->keyring_mode));
                        if (!info->keyring_mode)
                                return log_oom();
                }
                if (protect_proc_to_string(c->protect_proc)) {
                        info->protect_proc = strdup(protect_proc_to_string(c->protect_proc));
                        if (!info->protect_proc)
                                return log_oom();
                }
                if (proc_subset_to_string(c->proc_subset)) {
                        info->proc_subset = strdup(proc_subset_to_string(c->proc_subset));
                        if (!info->proc_subset)
                                return log_oom();
                }
                info->lock_personality = c->lock_personality;
                info->memory_deny_write_execute = c->memory_deny_write_execute;
                info->no_new_privileges = c->no_new_privileges;
                info->protect_hostname = c->protect_hostname;
                info->private_devices = c->private_devices;
                info->private_mounts = c->private_mounts;
                info->private_network = c->private_network;
                info->private_tmp = c->private_tmp;
                info->private_users = c->private_users;
                info->protect_control_groups = c->protect_control_groups;
                info->protect_kernel_modules = c->protect_kernel_modules;
                info->protect_kernel_tunables = c->protect_kernel_tunables;
                info->protect_kernel_logs = c->protect_kernel_logs;
                info->protect_clock = c->protect_clock;
                if (protect_home_to_string(c->protect_home)) {
                        info->protect_home = strdup(protect_home_to_string(c->protect_home));
                        if (!info->protect_home)
                                return log_oom();
                }
                if (protect_system_to_string(c->protect_system)) {
                        info->protect_system = strdup(protect_system_to_string(c->protect_system));
                        if (!info->protect_system)
                                return log_oom();
                }
                info->remove_ipc = c->remove_ipc;
                info->restrict_address_family_inet =
                        info->restrict_address_family_unix =
                        info->restrict_address_family_netlink =
                        info->restrict_address_family_packet =
                        info->restrict_address_family_other =
                        c->address_families_allow_list;

                void *key;
                SET_FOREACH(key, c->address_families) {
                        int family = PTR_TO_INT(key);
                        if (family == 0)
                                continue;
                        if (IN_SET(family, AF_INET, AF_INET6))
                                info->restrict_address_family_inet = !c->address_families_allow_list;
                        else if (family == AF_UNIX)
                                info->restrict_address_family_unix = !c->address_families_allow_list;
                        else if (family == AF_NETLINK)
                                info->restrict_address_family_netlink = !c->address_families_allow_list;
                        else if (family == AF_PACKET)
                                info->restrict_address_family_packet = !c->address_families_allow_list;
                        else
                                info->restrict_address_family_other = !c->address_families_allow_list;
                }

                info->restrict_namespaces = c->restrict_namespaces;
                info->restrict_realtime = c->restrict_realtime;
                info->restrict_suid_sgid = c->restrict_suid_sgid;
                if (c->root_directory) {
                        info->root_directory = strdup(c->root_directory);
                        if (!info->root_directory)
                                return log_oom();
                }
                if (c->root_image) {
                        info->root_image = strdup(c->root_image);
                        if (!info->root_image)
                                return log_oom();
                }
                info->_umask = c->umask;

#if HAVE_SECCOMP
                SET_FOREACH(key, c->syscall_archs) {
                        const char *name;

                        name = seccomp_arch_to_string(PTR_TO_UINT32(key) - 1);
                        if (!name)
                                continue;

                        if (set_put_strdup(&info->system_call_architectures, name) < 0)
                                return log_oom();
                }

                info->system_call_filter_allow_list = c->syscall_allow_list;

                void *id, *num;
                HASHMAP_FOREACH_KEY(num, id, c->syscall_filter) {
                        _cleanup_free_ char *name = NULL;

                        if (info->system_call_filter_allow_list && PTR_TO_INT(num) >= 0)
                                continue;

                        name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, PTR_TO_INT(id) - 1);
                        if (!name)
                                continue;

                        if (set_ensure_consume(&info->system_call_filter, &string_hash_ops_free, TAKE_PTR(name)) < 0)
                                return log_oom();
                }
#endif
        }

        if (g) {
                info->delegate = g->delegate;
                if (cgroup_device_policy_to_string(g->device_policy)) {
                        info->device_policy = strdup(cgroup_device_policy_to_string(g->device_policy));
                        if (!info->device_policy)
                                return log_oom();
                }

                struct in_addr_prefix *i;
                bool deny_ipv4 = false, deny_ipv6 = false;

                SET_FOREACH(i, g->ip_address_deny) {
                        if (i->family == AF_INET && i->prefixlen == 0)
                                deny_ipv4 = true;
                        else if (i->family == AF_INET6 && i->prefixlen == 0)
                                deny_ipv6 = true;
                }
                info->ip_address_deny_all = deny_ipv4 && deny_ipv6;

                info->ip_address_allow_localhost = info->ip_address_allow_other = false;
                SET_FOREACH(i, g->ip_address_allow) {
                        if (in_addr_is_localhost(i->family, &i->address))
                                info->ip_address_allow_localhost = true;
                        else
                                info->ip_address_allow_other = true;
                }

                info->ip_filters_custom_ingress = !strv_isempty(g->ip_filters_ingress);
                info->ip_filters_custom_egress = !strv_isempty(g->ip_filters_egress);

                LIST_FOREACH(device_allow, a, g->device_allow)
                        if (strv_extendf(&info->device_allow,
                                         "%s:%s",
                                         a->path,
                                         cgroup_device_permissions_to_string(a->permissions)) < 0)
                                return log_oom();
        }

        *ret_info = TAKE_PTR(info);

        return 0;
}

static int offline_security_check(Unit *u,
                                  unsigned threshold,
                                  JsonVariant *policy,
                                  PagerFlags pager_flags,
                                  JsonFormatFlags json_format_flags) {

        _cleanup_(table_unrefp) Table *overview_table = NULL;
        AnalyzeSecurityFlags flags = 0;
        _cleanup_(security_info_freep) SecurityInfo *info = NULL;
        int r;

        assert(u);

        if (DEBUG_LOGGING)
                unit_dump(u, stdout, "\t");

        r = get_security_info(u, unit_get_exec_context(u), unit_get_cgroup_context(u), &info);
        if (r < 0)
              return r;

        return assess(info, overview_table, flags, threshold, policy, pager_flags, json_format_flags);
}

static int offline_security_checks(
                char **filenames,
                JsonVariant *policy,
                RuntimeScope scope,
                bool check_man,
                bool run_generators,
                unsigned threshold,
                const char *root,
                const char *profile,
                PagerFlags pager_flags,
                JsonFormatFlags json_format_flags) {

        const ManagerTestRunFlags flags =
                MANAGER_TEST_RUN_MINIMAL |
                MANAGER_TEST_RUN_ENV_GENERATORS |
                MANAGER_TEST_RUN_IGNORE_DEPENDENCIES |
                MANAGER_TEST_DONT_OPEN_EXECUTOR |
                run_generators * MANAGER_TEST_RUN_GENERATORS;

        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *units[strv_length(filenames)];
        int r, k;
        size_t count = 0;

        if (strv_isempty(filenames))
                return 0;

        r = verify_set_unit_path(filenames);
        if (r < 0)
                return log_error_errno(r, "Failed to set unit load path: %m");

        r = manager_new(scope, flags, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize manager: %m");

        log_debug("Starting manager...");

        r = manager_startup(m, /* serialization= */ NULL, /* fds= */ NULL, root);
        if (r < 0)
                return r;

        if (profile) {
                /* Ensure the temporary directory is in the search path, so that we can add drop-ins. */
                r = strv_extend(&m->lookup_paths.search_path, m->lookup_paths.temporary_dir);
                if (r < 0)
                        return log_oom();
        }

        log_debug("Loading remaining units from the command line...");

        STRV_FOREACH(filename, filenames) {
                _cleanup_free_ char *prepared = NULL;

                log_debug("Handling %s...", *filename);

                k = verify_prepare_filename(*filename, &prepared);
                if (k < 0) {
                        log_warning_errno(k, "Failed to prepare filename %s: %m", *filename);
                        RET_GATHER(r, k);
                        continue;
                }

                /* When a portable image is analyzed, the profile is what provides a good chunk of
                 * the security-related settings, but they are obviously not shipped with the image.
                 * This allows to take them in consideration. */
                if (profile) {
                        _cleanup_free_ char *unit_name = NULL, *dropin = NULL, *profile_path = NULL;

                        r = path_extract_filename(prepared, &unit_name);
                        if (r < 0)
                                return log_oom();

                        dropin = strjoin(m->lookup_paths.temporary_dir, "/", unit_name, ".d/profile.conf");
                        if (!dropin)
                                return log_oom();
                        (void) mkdir_parents(dropin, 0755);

                        if (!is_path(profile)) {
                                r = find_portable_profile(profile, unit_name, &profile_path);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to find portable profile %s: %m", profile);
                                profile = profile_path;
                        }

                        r = copy_file(profile, dropin, 0, 0644, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy: %m");
                }

                k = manager_load_startable_unit_or_warn(m, NULL, prepared, &units[count]);
                if (k < 0) {
                        RET_GATHER(r, k);
                        continue;
                }

                count++;
        }

        for (size_t i = 0; i < count; i++)
                RET_GATHER(r, offline_security_check(units[i], threshold, policy, pager_flags, json_format_flags));

        return r;
}

static int analyze_security(sd_bus *bus,
                     char **units,
                     JsonVariant *policy,
                     RuntimeScope scope,
                     bool check_man,
                     bool run_generators,
                     bool offline,
                     unsigned threshold,
                     const char *root,
                     const char *profile,
                     JsonFormatFlags json_format_flags,
                     PagerFlags pager_flags,
                     AnalyzeSecurityFlags flags) {

        _cleanup_(table_unrefp) Table *overview_table = NULL;
        int ret = 0, r;

        assert(!!bus != offline);

        if (offline)
                return offline_security_checks(units, policy, scope, check_man, run_generators, threshold, root, profile, pager_flags, json_format_flags);

        if (strv_length(units) != 1) {
                overview_table = table_new("unit", "exposure", "predicate", "happy");
                if (!overview_table)
                        return log_oom();
        }

        if (strv_isempty(units)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_strv_free_ char **list = NULL;
                size_t n = 0;

                r = bus_call_method(
                                bus,
                                bus_systemd_mgr,
                                "ListUnits",
                                &error,
                                &reply,
                                NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to list units: %s", bus_error_message(&error, r));

                r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
                if (r < 0)
                        return bus_log_parse_error(r);

                for (;;) {
                        UnitInfo info;
                        char *copy = NULL;

                        r = bus_parse_unit_info(reply, &info);
                        if (r < 0)
                                return bus_log_parse_error(r);
                        if (r == 0)
                                break;

                        if (!endswith(info.id, ".service"))
                                continue;

                        if (!GREEDY_REALLOC(list, n + 2))
                                return log_oom();

                        copy = strdup(info.id);
                        if (!copy)
                                return log_oom();

                        list[n++] = copy;
                        list[n] = NULL;
                }

                strv_sort(list);

                flags |= ANALYZE_SECURITY_SHORT|ANALYZE_SECURITY_ONLY_LOADED|ANALYZE_SECURITY_ONLY_LONG_RUNNING;

                STRV_FOREACH(i, list) {
                        r = analyze_security_one(bus, *i, overview_table, flags, threshold, policy, pager_flags, json_format_flags);
                        if (r < 0 && ret >= 0)
                                ret = r;
                }

        } else
                STRV_FOREACH(i, units) {
                        _cleanup_free_ char *mangled = NULL, *instance = NULL;
                        const char *name;

                        if (!FLAGS_SET(flags, ANALYZE_SECURITY_SHORT) && i != units) {
                                putc('\n', stdout);
                                fflush(stdout);
                        }

                        r = unit_name_mangle(*i, 0, &mangled);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mangle unit name '%s': %m", *i);

                        if (!endswith(mangled, ".service"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unit %s is not a service unit, refusing.",
                                                       *i);

                        if (unit_name_is_valid(mangled, UNIT_NAME_TEMPLATE)) {
                                r = unit_name_replace_instance(mangled, "test-instance", &instance);
                                if (r < 0)
                                        return log_oom();

                                name = instance;
                        } else
                                name = mangled;

                        r = analyze_security_one(bus, name, overview_table, flags, threshold, policy, pager_flags, json_format_flags);
                        if (r < 0 && ret >= 0)
                                ret = r;
                }

        if (overview_table) {
                if (!FLAGS_SET(flags, ANALYZE_SECURITY_SHORT)) {
                        putc('\n', stdout);
                        fflush(stdout);
                }

                r = table_print_with_pager(overview_table, json_format_flags, pager_flags, /* show_header= */true);
                if (r < 0)
                        return log_error_errno(r, "Failed to output table: %m");
        }
        return ret;
}

int verb_security(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *policy = NULL;
        int r;
        unsigned line, column;

        if (!arg_offline) {
                r = acquire_bus(&bus, NULL);
                if (r < 0)
                        return bus_log_connect_error(r, arg_transport);
        }

        pager_open(arg_pager_flags);

        if (arg_security_policy) {
                r = json_parse_file(/*f=*/ NULL, arg_security_policy, /*flags=*/ 0, &policy, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse '%s' at %u:%u: %m", arg_security_policy, line, column);
        } else {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *pp = NULL;

                r = search_and_fopen_nulstr("systemd-analyze-security.policy", "re", /*root=*/ NULL, CONF_PATHS_NULSTR("systemd"), &f, &pp);
                if (r < 0 && r != -ENOENT)
                        return r;

                if (f) {
                        r = json_parse_file(f, pp, /*flags=*/ 0, &policy, &line, &column);
                        if (r < 0)
                                return log_error_errno(r, "[%s:%u:%u] Failed to parse JSON policy: %m", pp, line, column);
                }
        }

        return analyze_security(
                        bus,
                        strv_skip(argv, 1),
                        policy,
                        arg_runtime_scope,
                        arg_man,
                        arg_generators,
                        arg_offline,
                        arg_threshold,
                        arg_root,
                        arg_profile,
                        arg_json_format_flags,
                        arg_pager_flags,
                        /*flags=*/ 0);
}
