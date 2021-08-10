/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"

#include "format-table.h"
#include "hashmap.h"

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
        bool device_allow_non_empty;

        Set *system_call_architectures;

        bool system_call_filter_allow_list;
        Hashmap *system_call_filter;

        mode_t _umask;
} SecurityInfo;

typedef enum AnalyzeSecurityFlags {
        ANALYZE_SECURITY_SHORT                 = 1 << 0,
        ANALYZE_SECURITY_ONLY_LOADED           = 1 << 1,
        ANALYZE_SECURITY_ONLY_LONG_RUNNING     = 1 << 2,
        ANALYZE_SECURITY_EXPOSURE_ABOVE_MEDIUM = 1 << 3,
} AnalyzeSecurityFlags;

int analyze_security(sd_bus *bus, char **units, AnalyzeSecurityFlags flags);
int assess(const SecurityInfo *info, Table *overview_table, AnalyzeSecurityFlags flags);
