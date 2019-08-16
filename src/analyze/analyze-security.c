/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sched.h>
#include <sys/utsname.h>

#include "analyze-security.h"
#include "bus-error.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "env-util.h"
#include "format-table.h"
#include "in-addr-util.h"
#include "locale-util.h"
#include "macro.h"
#include "missing.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#if HAVE_SECCOMP
#  include "seccomp-util.h"
#endif
#include "set.h"
#include "stdio-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit-def.h"
#include "unit-name.h"

struct security_info {
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

        char *protect_home;
        char *protect_system;

        bool remove_ipc;

        bool restrict_address_family_inet;
        bool restrict_address_family_unix;
        bool restrict_address_family_netlink;
        bool restrict_address_family_packet;
        bool restrict_address_family_other;

        uint64_t restrict_namespaces;
        bool restrict_realtime;
        bool restrict_suid_sgid;

        char *root_directory;
        char *root_image;

        bool delegate;
        char *device_policy;
        bool device_allow_non_empty;

        char **system_call_architectures;

        bool system_call_filter_whitelist;
        Set *system_call_filter;

        uint32_t _umask;
};

struct security_assessor {
        const char *id;
        const char *description_good;
        const char *description_bad;
        const char *description_na;
        const char *url;
        uint64_t weight;
        uint64_t range;
        int (*assess)(
                const struct security_assessor *a,
                const struct security_info *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description);
        size_t offset;
        uint64_t parameter;
        bool default_dependencies_only;
};

static void security_info_free(struct security_info *i) {
        if (!i)
                return;

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
        free(i->notify_access);

        free(i->device_policy);

        strv_free(i->supplementary_groups);
        strv_free(i->system_call_architectures);

        set_free_free(i->system_call_filter);
}

static bool security_info_runs_privileged(const struct security_info *i)  {
        assert(i);

        if (STRPTR_IN_SET(i->user, "0", "root"))
                return true;

        if (i->dynamic_user)
                return false;

        return isempty(i->user);
}

static int assess_bool(
                const struct security_assessor *a,
                const struct security_info *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        const bool *b = data;

        assert(b);
        assert(ret_badness);
        assert(ret_description);

        *ret_badness = a->parameter ? *b : !*b;
        *ret_description = NULL;

        return 0;
}

static int assess_user(
                const struct security_assessor *a,
                const struct security_info *info,
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
                const struct security_info *info,
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
                const struct security_info *info,
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
                const struct security_info *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness =
                empty_or_root(info->root_directory) ||
                empty_or_root(info->root_image);
        *ret_description = NULL;

        return 0;
}

static int assess_capability_bounding_set(
                const struct security_assessor *a,
                const struct security_info *info,
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
                const struct security_info *info,
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
                const struct security_info *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness = !streq_ptr(info->keyring_mode, "private");
        *ret_description = NULL;

        return 0;
}

static int assess_notify_access(
                const struct security_assessor *a,
                const struct security_info *info,
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
                const struct security_info *info,
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
                const struct security_info *info,
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
                const struct security_info *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        assert(ret_badness);
        assert(ret_description);

        *ret_badness = !!(info->restrict_namespaces & a->parameter);
        *ret_description = NULL;

        return 0;
}

static int assess_system_call_architectures(
                const struct security_assessor *a,
                const struct security_info *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        char *d;
        uint64_t b;

        assert(ret_badness);
        assert(ret_description);

        if (strv_isempty(info->system_call_architectures)) {
                b = 10;
                d = strdup("Service may execute system calls with all ABIs");
        } else if (strv_equal(info->system_call_architectures, STRV_MAKE("native"))) {
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

#if HAVE_SECCOMP

static bool syscall_names_in_filter(Set *s, bool whitelist, const SyscallFilterSet *f) {
        const char *syscall;

        NULSTR_FOREACH(syscall, f->value) {
                int id;

                if (syscall[0] == '@') {
                        const SyscallFilterSet *g;

                        assert_se(g = syscall_filter_set_find(syscall));
                        if (syscall_names_in_filter(s, whitelist, g))
                                return true; /* bad! */

                        continue;
                }

                /* Let's see if the system call actually exists on this platform, before complaining */
                id = seccomp_syscall_resolve_name(syscall);
                if (id < 0)
                        continue;

                if (set_contains(s, syscall) == whitelist) {
                        log_debug("Offending syscall filter item: %s", syscall);
                        return true; /* bad! */
                }
        }

        return false;
}

static int assess_system_call_filter(
                const struct security_assessor *a,
                const struct security_info *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        const SyscallFilterSet *f;
        char *d = NULL;
        uint64_t b;

        assert(a);
        assert(info);
        assert(ret_badness);
        assert(ret_description);

        assert(a->parameter < _SYSCALL_FILTER_SET_MAX);
        f = syscall_filter_sets + a->parameter;

        if (!info->system_call_filter_whitelist && set_isempty(info->system_call_filter)) {
                d = strdup("Service does not filter system calls");
                b = 10;
        } else {
                bool bad;

                log_debug("Analyzing system call filter, checking against: %s", f->name);
                bad = syscall_names_in_filter(info->system_call_filter, info->system_call_filter_whitelist, f);
                log_debug("Result: %s", bad ? "bad" : "good");

                if (info->system_call_filter_whitelist) {
                        if (bad) {
                                (void) asprintf(&d, "System call whitelist defined for service, and %s is included", f->name);
                                b = 9;
                        } else {
                                (void) asprintf(&d, "System call whitelist defined for service, and %s is not included", f->name);
                                b = 0;
                        }
                } else {
                        if (bad) {
                                (void) asprintf(&d, "System call blacklist defined for service, and %s is not included", f->name);
                                b = 10;
                        } else {
                                (void) asprintf(&d, "System call blacklist defined for service, and %s is included", f->name);
                                b = 5;
                        }
                }
        }

        if (!d)
                return log_oom();

        *ret_badness = b;
        *ret_description = d;

        return 0;
}

#endif

static int assess_ip_address_allow(
                const struct security_assessor *a,
                const struct security_info *info,
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
                d = strdup("Service does not define an IP address whitelist");
                b = 10;
        } else if (info->ip_address_allow_other) {
                d = strdup("Service defines IP address whitelist with non-localhost entries");
                b = 5;
        } else if (info->ip_address_allow_localhost) {
                d = strdup("Service defines IP address whitelist with only localhost entries");
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
                const struct security_info *info,
                const void *data,
                uint64_t *ret_badness,
                char **ret_description) {

        char *d = NULL;
        uint64_t b;

        assert(info);
        assert(ret_badness);
        assert(ret_description);

        if (STRPTR_IN_SET(info->device_policy, "strict", "closed")) {

                if (info->device_allow_non_empty) {
                        d = strdup("Service has a device ACL with some special devices");
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
                const struct security_info *info,
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
                .description_bad = "Service runs as root user",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#User=",
                .weight = 2000,
                .range = 10,
                .assess = assess_user,
        },
        {
                .id = "SupplementaryGroups=",
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
                .description_good = "Service has no access to hardware devices",
                .description_bad = "Service potentially has access to hardware devices",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateDevices=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, private_devices),
        },
        {
                .id = "PrivateMounts=",
                .description_good = "Service cannot install system mounts",
                .description_bad = "Service may install system mounts",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateMounts=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, private_mounts),
        },
        {
                .id = "PrivateNetwork=",
                .description_good = "Service has no access to the host's network",
                .description_bad = "Service has access to the host's network",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateNetwork=",
                .weight = 2500,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, private_network),
        },
        {
                .id = "PrivateTmp=",
                .description_good = "Service has no access to other software's temporary files",
                .description_bad = "Service has access to other software's temporary files",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateTmp=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, private_tmp),
                .default_dependencies_only = true,
        },
        {
                .id = "PrivateUsers=",
                .description_good = "Service does not have access to other users",
                .description_bad = "Service has access to other users",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateUsers=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, private_users),
        },
        {
                .id = "ProtectControlGroups=",
                .description_good = "Service cannot modify the control group file system",
                .description_bad = "Service may modify to the control group file system",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectControlGroups=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, protect_control_groups),
        },
        {
                .id = "ProtectKernelModules=",
                .description_good = "Service cannot load or read kernel modules",
                .description_bad = "Service may load or read kernel modules",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelModules=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, protect_kernel_modules),
        },
        {
                .id = "ProtectKernelTunables=",
                .description_good = "Service cannot alter kernel tunables (/proc/sys, …)",
                .description_bad = "Service may alter kernel tunables",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelTunables=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, protect_kernel_tunables),
        },
        {
                .id = "ProtectHome=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHome=",
                .weight = 1000,
                .range = 10,
                .assess = assess_protect_home,
                .default_dependencies_only = true,
        },
        {
                .id = "ProtectHostname=",
                .description_good = "Service cannot change system host/domainname",
                .description_bad = "Service may change system host/domainname",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHostname=",
                .weight = 50,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, protect_hostname),
        },
        {
                .id = "ProtectSystem=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=",
                .weight = 1000,
                .range = 10,
                .assess = assess_protect_system,
                .default_dependencies_only = true,
        },
        {
                .id = "RootDirectory=/RootImage=",
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
                .description_good = "Service cannot change ABI personality",
                .description_bad = "Service may change ABI personality",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#LockPersonality=",
                .weight = 100,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, lock_personality),
        },
        {
                .id = "MemoryDenyWriteExecute=",
                .description_good = "Service cannot create writable executable memory mappings",
                .description_bad = "Service may create writable executable memory mappings",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#MemoryDenyWriteExecute=",
                .weight = 100,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, memory_deny_write_execute),
        },
        {
                .id = "NoNewPrivileges=",
                .description_good = "Service processes cannot acquire new privileges",
                .description_bad = "Service processes may acquire new privileges",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#NoNewPrivileges=",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, no_new_privileges),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_SYS_ADMIN",
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
                .description_good = "Service has no network configuration privileges",
                .description_bad = "Service has network configuration privileges",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 1000,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_NET_ADMIN),
        },
        {
                .id = "CapabilityBoundingSet=~CAP_RAWIO",
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
                .description_good = "Service cannot use acct()",
                .description_bad = "Service may use acct()",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet=",
                .weight = 25,
                .range = 1,
                .assess = assess_capability_bounding_set,
                .parameter = (UINT64_C(1) << CAP_SYS_PACCT),
        },
        {
                .id = "UMask=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#UMask=",
                .weight = 100,
                .range = 10,
                .assess = assess_umask,
        },
        {
                .id = "KeyringMode=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#KeyringMode=",
                .description_good = "Service doesn't share key material with other services",
                .description_bad = "Service shares key material with other service",
                .weight = 1000,
                .range = 1,
                .assess = assess_keyring_mode,
        },
        {
                .id = "NotifyAccess=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#NotifyAccess=",
                .description_good = "Service child processes cannot alter service state",
                .description_bad = "Service child processes may alter service state",
                .weight = 1000,
                .range = 1,
                .assess = assess_notify_access,
        },
        {
                .id = "RemoveIPC=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RemoveIPC=",
                .description_good = "Service user cannot leave SysV IPC objects around",
                .description_bad = "Service user may leave SysV IPC objects around",
                .description_na = "Service runs as root, option does not apply",
                .weight = 100,
                .range = 1,
                .assess = assess_remove_ipc,
                .offset = offsetof(struct security_info, remove_ipc),
        },
        {
                .id = "Delegate=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Delegate=",
                .description_good = "Service does not maintain its own delegated control group subtree",
                .description_bad = "Service maintains its own delegated control group subtree",
                .weight = 100,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, delegate),
                .parameter = true, /* invert! */
        },
        {
                .id = "RestrictRealtime=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictRealtime=",
                .description_good = "Service realtime scheduling access is restricted",
                .description_bad = "Service may acquire realtime scheduling",
                .weight = 500,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, restrict_realtime),
        },
        {
                .id = "RestrictSUIDSGID=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictSUIDSGID=",
                .description_good = "SUID/SGID file creation by service is restricted",
                .description_bad = "Service may create SUID/SGID files",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, restrict_suid_sgid),
        },
        {
                .id = "RestrictNamespaces=~CLONE_NEWUSER",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create user namespaces",
                .description_bad = "Service may create user namespaces",
                .weight = 1500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWUSER,
        },
        {
                .id = "RestrictNamespaces=~CLONE_NEWNS",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create file system namespaces",
                .description_bad = "Service may create file system namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWNS,
        },
        {
                .id = "RestrictNamespaces=~CLONE_NEWIPC",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create IPC namespaces",
                .description_bad = "Service may create IPC namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWIPC,
        },
        {
                .id = "RestrictNamespaces=~CLONE_NEWPID",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create process namespaces",
                .description_bad = "Service may create process namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWPID,
        },
        {
                .id = "RestrictNamespaces=~CLONE_NEWCGROUP",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create cgroup namespaces",
                .description_bad = "Service may create cgroup namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWCGROUP,
        },
        {
                .id = "RestrictNamespaces=~CLONE_NEWNET",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces=",
                .description_good = "Service cannot create network namespaces",
                .description_bad = "Service may create network namespaces",
                .weight = 500,
                .range = 1,
                .assess = assess_restrict_namespaces,
                .parameter = CLONE_NEWNET,
        },
        {
                .id = "RestrictNamespaces=~CLONE_NEWUTS",
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
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate Internet sockets",
                .description_bad = "Service may allocate Internet sockets",
                .weight = 1500,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, restrict_address_family_inet),
        },
        {
                .id = "RestrictAddressFamilies=~AF_UNIX",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate local sockets",
                .description_bad = "Service may allocate local sockets",
                .weight = 25,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, restrict_address_family_unix),
        },
        {
                .id = "RestrictAddressFamilies=~AF_NETLINK",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate netlink sockets",
                .description_bad = "Service may allocate netlink sockets",
                .weight = 200,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, restrict_address_family_netlink),
        },
        {
                .id = "RestrictAddressFamilies=~AF_PACKET",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate packet sockets",
                .description_bad = "Service may allocate packet sockets",
                .weight = 1000,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, restrict_address_family_packet),
        },
        {
                .id = "RestrictAddressFamilies=~…",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=",
                .description_good = "Service cannot allocate exotic sockets",
                .description_bad = "Service may allocate exotic sockets",
                .weight = 1250,
                .range = 1,
                .assess = assess_bool,
                .offset = offsetof(struct security_info, restrict_address_family_other),
        },
        {
                .id = "SystemCallArchitectures=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallArchitectures=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_architectures,
        },
#if HAVE_SECCOMP
        {
                .id = "SystemCallFilter=~@swap",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_SWAP,
        },
        {
                .id = "SystemCallFilter=~@obsolete",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 250,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_OBSOLETE,
        },
        {
                .id = "SystemCallFilter=~@clock",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_CLOCK,
        },
        {
                .id = "SystemCallFilter=~@cpu-emulation",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 250,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_CPU_EMULATION,
        },
        {
                .id = "SystemCallFilter=~@debug",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_DEBUG,
        },
        {
                .id = "SystemCallFilter=~@mount",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_MOUNT,
        },
        {
                .id = "SystemCallFilter=~@module",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_MODULE,
        },
        {
                .id = "SystemCallFilter=~@raw-io",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_RAW_IO,
        },
        {
                .id = "SystemCallFilter=~@reboot",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 1000,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_REBOOT,
        },
        {
                .id = "SystemCallFilter=~@privileged",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 700,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_PRIVILEGED,
        },
        {
                .id = "SystemCallFilter=~@resources",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=",
                .weight = 700,
                .range = 10,
                .assess = assess_system_call_filter,
                .parameter = SYSCALL_FILTER_SET_RESOURCES,
        },
#endif
        {
                .id = "IPAddressDeny=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#IPAddressDeny=",
                .weight = 1000,
                .range = 10,
                .assess = assess_ip_address_allow,
        },
        {
                .id = "DeviceAllow=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#DeviceAllow=",
                .weight = 1000,
                .range = 10,
                .assess = assess_device_allow,
        },
        {
                .id = "AmbientCapabilities=",
                .url = "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#AmbientCapabilities=",
                .description_good = "Service process does not receive ambient capabilities",
                .description_bad = "Service process receives ambient capabilities",
                .weight = 500,
                .range = 1,
                .assess = assess_ambient_capabilities,
        },
};

static int assess(const struct security_info *info, Table *overview_table, AnalyzeSecurityFlags flags) {
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
                details_table = table_new(" ", "name", "description", "weight", "badness", "range", "exposure");
                if (!details_table)
                        return log_oom();

                (void) table_set_sort(details_table, 3, 1, (size_t) -1);
                (void) table_set_reverse(details_table, 3, true);

                if (getenv_bool("SYSTEMD_ANALYZE_DEBUG") <= 0)
                        (void) table_set_display(details_table, 0, 1, 2, 6, (size_t) -1);
        }

        for (i = 0; i < ELEMENTSOF(security_assessor_table); i++) {
                const struct security_assessor *a = security_assessor_table + i;
                _cleanup_free_ char *d = NULL;
                uint64_t badness;
                void *data;

                data = (uint8_t *) info + a->offset;

                if (a->default_dependencies_only && !info->default_dependencies) {
                        badness = UINT64_MAX;
                        d = strdup("Service runs in special boot phase, option does not apply");
                        if (!d)
                                return log_oom();
                } else {
                        r = a->assess(a, info, data, &badness, &d);
                        if (r < 0)
                                return r;
                }

                assert(a->range > 0);

                if (badness != UINT64_MAX) {
                        assert(badness <= a->range);

                        badness_sum += DIV_ROUND_UP(badness * a->weight, a->range);
                        weight_sum += a->weight;
                }

                if (details_table) {
                        const char *checkmark, *description, *color = NULL;
                        TableCell *cell;

                        if (badness == UINT64_MAX) {
                                checkmark = " ";
                                description = a->description_na;
                                color = NULL;
                        } else if (badness == a->range) {
                                checkmark = special_glyph(SPECIAL_GLYPH_CROSS_MARK);
                                description = a->description_bad;
                                color = ansi_highlight_red();
                        } else if (badness == 0) {
                                checkmark = special_glyph(SPECIAL_GLYPH_CHECK_MARK);
                                description = a->description_good;
                                color = ansi_highlight_green();
                        } else {
                                checkmark = special_glyph(SPECIAL_GLYPH_CROSS_MARK);
                                description = NULL;
                                color = ansi_highlight_red();
                        }

                        if (d)
                                description = d;

                        r = table_add_cell_full(details_table, &cell, TABLE_STRING, checkmark, 1, 1, 0, 0, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add cell to table: %m");
                        if (color)
                                (void) table_set_color(details_table, cell, color);

                        r = table_add_many(details_table,
                                           TABLE_STRING, a->id, TABLE_SET_URL, a->url,
                                           TABLE_STRING, description,
                                           TABLE_UINT64, a->weight, TABLE_SET_ALIGN_PERCENT, 100,
                                           TABLE_UINT64, badness, TABLE_SET_ALIGN_PERCENT, 100,
                                           TABLE_UINT64, a->range, TABLE_SET_ALIGN_PERCENT, 100,
                                           TABLE_EMPTY, TABLE_SET_ALIGN_PERCENT, 100);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add cells to table: %m");
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

                        assert_se(weight = table_get_at(details_table, row, 3));
                        assert_se(badness = table_get_at(details_table, row, 4));
                        assert_se(range = table_get_at(details_table, row, 5));

                        if (*badness == UINT64_MAX || *badness == 0)
                                continue;

                        assert_se(cell = table_get_cell(details_table, row, 6));

                        x = DIV_ROUND_UP(DIV_ROUND_UP(*badness * *weight * 100U, *range), weight_sum);
                        xsprintf(buf, "%" PRIu64 ".%" PRIu64, x / 10, x % 10);

                        r = table_update(details_table, cell, TABLE_STRING, buf);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update cell in table: %m");
                }

                r = table_print(details_table, stdout);
                if (r < 0)
                        return log_error_errno(r, "Failed to output table: %m");
        }

        exposure = DIV_ROUND_UP(badness_sum * 100U, weight_sum);

        for (i = 0; i < ELEMENTSOF(badness_table); i++)
                if (exposure >= badness_table[i].exposure)
                        break;

        assert(i < ELEMENTSOF(badness_table));

        if (details_table) {
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
                       special_glyph(SPECIAL_GLYPH_ARROW),
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
                TableCell *cell;

                r = table_add_cell(overview_table, &cell, TABLE_STRING, info->id);
                if (r < 0)
                        return log_error_errno(r, "Failed to add cell to table: %m");
                if (info->fragment_path) {
                        _cleanup_free_ char *url = NULL;

                        r = file_url_from_path(info->fragment_path, &url);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate URL from path: %m");

                        (void) table_set_url(overview_table, cell, url);
                }

                xsprintf(buf, "%" PRIu64 ".%" PRIu64, exposure / 10, exposure % 10);
                r = table_add_cell(overview_table, &cell, TABLE_STRING, buf);
                if (r < 0)
                        return log_error_errno(r, "Failed to add cell to table: %m");
                (void) table_set_align_percent(overview_table, cell, 100);

                r = table_add_cell(overview_table, &cell, TABLE_STRING, badness_table[i].name);
                if (r < 0)
                        return log_error_errno(r, "Failed to add cell to table: %m");
                (void) table_set_color(overview_table, cell, strempty(badness_table[i].color));

                r = table_add_cell(overview_table, NULL, TABLE_STRING, special_glyph(badness_table[i].smiley));
                if (r < 0)
                        return log_error_errno(r, "Failed to add cell to table: %m");
        }

        return 0;
}

static int property_read_restrict_address_families(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        struct security_info *info = userdata;
        int whitelist, r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'r', "bas");
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "b", &whitelist);
        if (r < 0)
                return r;

        info->restrict_address_family_inet =
                info->restrict_address_family_unix =
                info->restrict_address_family_netlink =
                info->restrict_address_family_packet =
                info->restrict_address_family_other = whitelist;

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
                        info->restrict_address_family_inet = !whitelist;
                else if (streq(name, "AF_UNIX"))
                        info->restrict_address_family_unix = !whitelist;
                else if (streq(name, "AF_NETLINK"))
                        info->restrict_address_family_netlink = !whitelist;
                else if (streq(name, "AF_PACKET"))
                        info->restrict_address_family_packet = !whitelist;
                else
                        info->restrict_address_family_other = !whitelist;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return sd_bus_message_exit_container(m);
}

static int property_read_system_call_filter(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        struct security_info *info = userdata;
        int whitelist, r;

        assert(bus);
        assert(member);
        assert(m);

        r = sd_bus_message_enter_container(m, 'r', "bas");
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "b", &whitelist);
        if (r < 0)
                return r;

        info->system_call_filter_whitelist = whitelist;

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

                r = set_ensure_allocated(&info->system_call_filter, &string_hash_ops);
                if (r < 0)
                        return r;

                r = set_put_strdup(info->system_call_filter, name);
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

        struct security_info *info = userdata;
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

        struct security_info *info = userdata;
        _cleanup_(strv_freep) char **l = NULL;
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
                info->ip_filters_custom_ingress = !strv_isempty(l);

        return 0;
}

static int property_read_device_allow(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        struct security_info *info = userdata;
        size_t n = 0;
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

                n++;
        }

        info->device_allow_non_empty = n > 0;

        return sd_bus_message_exit_container(m);
}

static int acquire_security_info(sd_bus *bus, const char *name, struct security_info *info, AnalyzeSecurityFlags flags) {

        static const struct bus_properties_map security_map[] = {
                { "AmbientCapabilities",     "t",       NULL,                                    offsetof(struct security_info, ambient_capabilities)      },
                { "CapabilityBoundingSet",   "t",       NULL,                                    offsetof(struct security_info, capability_bounding_set)   },
                { "DefaultDependencies",     "b",       NULL,                                    offsetof(struct security_info, default_dependencies)      },
                { "Delegate",                "b",       NULL,                                    offsetof(struct security_info, delegate)                  },
                { "DeviceAllow",             "a(ss)",   property_read_device_allow,              0                                                         },
                { "DevicePolicy",            "s",       NULL,                                    offsetof(struct security_info, device_policy)             },
                { "DynamicUser",             "b",       NULL,                                    offsetof(struct security_info, dynamic_user)              },
                { "FragmentPath",            "s",       NULL,                                    offsetof(struct security_info, fragment_path)             },
                { "IPAddressAllow",          "a(iayu)", property_read_ip_address_allow,          0                                                         },
                { "IPAddressDeny",           "a(iayu)", property_read_ip_address_allow,          0                                                         },
                { "IPIngressFilterPath",     "as",      property_read_ip_filters,                0                                                         },
                { "IPEgressFilterPath",      "as",      property_read_ip_filters,                0                                                         },
                { "Id",                      "s",       NULL,                                    offsetof(struct security_info, id)                        },
                { "KeyringMode",             "s",       NULL,                                    offsetof(struct security_info, keyring_mode)              },
                { "LoadState",               "s",       NULL,                                    offsetof(struct security_info, load_state)                },
                { "LockPersonality",         "b",       NULL,                                    offsetof(struct security_info, lock_personality)          },
                { "MemoryDenyWriteExecute",  "b",       NULL,                                    offsetof(struct security_info, memory_deny_write_execute) },
                { "NoNewPrivileges",         "b",       NULL,                                    offsetof(struct security_info, no_new_privileges)         },
                { "NotifyAccess",            "s",       NULL,                                    offsetof(struct security_info, notify_access)             },
                { "PrivateDevices",          "b",       NULL,                                    offsetof(struct security_info, private_devices)           },
                { "PrivateMounts",           "b",       NULL,                                    offsetof(struct security_info, private_mounts)            },
                { "PrivateNetwork",          "b",       NULL,                                    offsetof(struct security_info, private_network)           },
                { "PrivateTmp",              "b",       NULL,                                    offsetof(struct security_info, private_tmp)               },
                { "PrivateUsers",            "b",       NULL,                                    offsetof(struct security_info, private_users)             },
                { "ProtectControlGroups",    "b",       NULL,                                    offsetof(struct security_info, protect_control_groups)    },
                { "ProtectHome",             "s",       NULL,                                    offsetof(struct security_info, protect_home)              },
                { "ProtectHostname",         "b",       NULL,                                    offsetof(struct security_info, protect_hostname)          },
                { "ProtectKernelModules",    "b",       NULL,                                    offsetof(struct security_info, protect_kernel_modules)    },
                { "ProtectKernelTunables",   "b",       NULL,                                    offsetof(struct security_info, protect_kernel_tunables)   },
                { "ProtectSystem",           "s",       NULL,                                    offsetof(struct security_info, protect_system)            },
                { "RemoveIPC",               "b",       NULL,                                    offsetof(struct security_info, remove_ipc)                },
                { "RestrictAddressFamilies", "(bas)",   property_read_restrict_address_families, 0                                                         },
                { "RestrictNamespaces",      "t",       NULL,                                    offsetof(struct security_info, restrict_namespaces)       },
                { "RestrictRealtime",        "b",       NULL,                                    offsetof(struct security_info, restrict_realtime)         },
                { "RestrictSUIDSGID",        "b",       NULL,                                    offsetof(struct security_info, restrict_suid_sgid)        },
                { "RootDirectory",           "s",       NULL,                                    offsetof(struct security_info, root_directory)            },
                { "RootImage",               "s",       NULL,                                    offsetof(struct security_info, root_image)                },
                { "SupplementaryGroups",     "as",      NULL,                                    offsetof(struct security_info, supplementary_groups)      },
                { "SystemCallArchitectures", "as",      NULL,                                    offsetof(struct security_info, system_call_architectures) },
                { "SystemCallFilter",        "(as)",    property_read_system_call_filter,        0                                                         },
                { "Type",                    "s",       NULL,                                    offsetof(struct security_info, type)                      },
                { "UMask",                   "u",       NULL,                                    offsetof(struct security_info, _umask)                    },
                { "User",                    "s",       NULL,                                    offsetof(struct security_info, user)                      },
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

        if (info->private_devices)
                info->capability_bounding_set &= ~((UINT64_C(1) << CAP_MKNOD) |
                                                   (UINT64_C(1) << CAP_SYS_RAWIO));

        return 0;
}

static int analyze_security_one(sd_bus *bus, const char *name, Table *overview_table, AnalyzeSecurityFlags flags) {
        _cleanup_(security_info_free) struct security_info info = {
                .default_dependencies = true,
                .capability_bounding_set = UINT64_MAX,
                .restrict_namespaces = UINT64_MAX,
                ._umask = 0002,
        };
        int r;

        assert(bus);
        assert(name);

        r = acquire_security_info(bus, name, &info, flags);
        if (r == -EMEDIUMTYPE) /* Ignore this one because not loaded or Type is oneshot */
                return 0;
        if (r < 0)
                return r;

        r = assess(&info, overview_table, flags);
        if (r < 0)
                return r;

        return 0;
}

int analyze_security(sd_bus *bus, char **units, AnalyzeSecurityFlags flags) {
        _cleanup_(table_unrefp) Table *overview_table = NULL;
        int ret = 0, r;

        assert(bus);

        if (strv_length(units) != 1) {
                overview_table = table_new("unit", "exposure", "predicate", "happy");
                if (!overview_table)
                        return log_oom();
        }

        if (strv_isempty(units)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_strv_free_ char **list = NULL;
                size_t allocated = 0, n = 0;
                char **i;

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
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

                        if (!GREEDY_REALLOC(list, allocated, n + 2))
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
                        r = analyze_security_one(bus, *i, overview_table, flags);
                        if (r < 0 && ret >= 0)
                                ret = r;
                }

        } else {
                char **i;

                STRV_FOREACH(i, units) {
                        _cleanup_free_ char *mangled = NULL, *instance = NULL;
                        const char *name;

                        if (!FLAGS_SET(flags, ANALYZE_SECURITY_SHORT) && i != units) {
                                putc('\n', stdout);
                                fflush(stdout);
                        }

                        r = unit_name_mangle_with_suffix(*i, 0, ".service", &mangled);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mangle unit name '%s': %m", *i);

                        if (!endswith(mangled, ".service")) {
                                log_error("Unit %s is not a service unit, refusing.", *i);
                                return -EINVAL;
                        }

                        if (unit_name_is_valid(mangled, UNIT_NAME_TEMPLATE)) {
                                r = unit_name_replace_instance(mangled, "test-instance", &instance);
                                if (r < 0)
                                        return log_oom();

                                name = instance;
                        } else
                                name = mangled;

                        r = analyze_security_one(bus, name, overview_table, flags);
                        if (r < 0 && ret >= 0)
                                ret = r;
                }
        }

        if (overview_table) {
                if (!FLAGS_SET(flags, ANALYZE_SECURITY_SHORT)) {
                        putc('\n', stdout);
                        fflush(stdout);
                }

                r = table_print(overview_table, stdout);
                if (r < 0)
                        return log_error_errno(r, "Failed to output table: %m");
        }

        return ret;
}
