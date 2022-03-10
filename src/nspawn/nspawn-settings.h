/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sched.h>
#include <stdio.h>

#if HAVE_SECCOMP
#include <seccomp.h>
#endif

#include "sd-bus.h"
#include "sd-id128.h"

#include "capability-util.h"
#include "conf-parser.h"
#include "cpu-set-util.h"
#include "macro.h"
#include "missing_resource.h"
#include "nspawn-expose-ports.h"
#include "nspawn-mount.h"
#include "time-util.h"

typedef enum StartMode {
        START_PID1, /* Run parameters as command line as process 1 */
        START_PID2, /* Use stub init process as PID 1, run parameters as command line as process 2 */
        START_BOOT, /* Search for init system, pass arguments as parameters */
        _START_MODE_MAX,
        _START_MODE_INVALID = -EINVAL,
} StartMode;

typedef enum UserNamespaceMode {
        USER_NAMESPACE_NO,
        USER_NAMESPACE_FIXED,
        USER_NAMESPACE_PICK,
        _USER_NAMESPACE_MODE_MAX,
        _USER_NAMESPACE_MODE_INVALID = -EINVAL,
} UserNamespaceMode;

typedef enum UserNamespaceOwnership {
        USER_NAMESPACE_OWNERSHIP_OFF,
        USER_NAMESPACE_OWNERSHIP_CHOWN,
        USER_NAMESPACE_OWNERSHIP_MAP,
        USER_NAMESPACE_OWNERSHIP_AUTO,
        _USER_NAMESPACE_OWNERSHIP_MAX,
        _USER_NAMESPACE_OWNERSHIP_INVALID = -1,
} UserNamespaceOwnership;

typedef enum ResolvConfMode {
        RESOLV_CONF_OFF,
        RESOLV_CONF_COPY_HOST,     /* /etc/resolv.conf */
        RESOLV_CONF_COPY_STATIC,   /* /usr/lib/systemd/resolv.conf */
        RESOLV_CONF_COPY_UPLINK,   /* /run/systemd/resolve/resolv.conf */
        RESOLV_CONF_COPY_STUB,     /* /run/systemd/resolve/stub-resolv.conf */
        RESOLV_CONF_REPLACE_HOST,
        RESOLV_CONF_REPLACE_STATIC,
        RESOLV_CONF_REPLACE_UPLINK,
        RESOLV_CONF_REPLACE_STUB,
        RESOLV_CONF_BIND_HOST,
        RESOLV_CONF_BIND_STATIC,
        RESOLV_CONF_BIND_UPLINK,
        RESOLV_CONF_BIND_STUB,
        RESOLV_CONF_DELETE,
        RESOLV_CONF_AUTO,
        _RESOLV_CONF_MODE_MAX,
        _RESOLV_CONF_MODE_INVALID = -EINVAL,
} ResolvConfMode;

typedef enum LinkJournal {
        LINK_NO,
        LINK_AUTO,
        LINK_HOST,
        LINK_GUEST,
        _LINK_JOURNAL_MAX,
        _LINK_JOURNAL_INVALID = -EINVAL,
} LinkJournal;

typedef enum TimezoneMode {
        TIMEZONE_OFF,
        TIMEZONE_COPY,
        TIMEZONE_BIND,
        TIMEZONE_SYMLINK,
        TIMEZONE_DELETE,
        TIMEZONE_AUTO,
        _TIMEZONE_MODE_MAX,
        _TIMEZONE_MODE_INVALID = -EINVAL,
} TimezoneMode;

typedef enum ConsoleMode {
        CONSOLE_INTERACTIVE,
        CONSOLE_READ_ONLY,
        CONSOLE_PASSIVE,
        CONSOLE_PIPE,
        _CONSOLE_MODE_MAX,
        _CONSOLE_MODE_INVALID = -EINVAL,
} ConsoleMode;

typedef enum SettingsMask {
        SETTING_START_MODE        = UINT64_C(1) << 0,
        SETTING_ENVIRONMENT       = UINT64_C(1) << 1,
        SETTING_USER              = UINT64_C(1) << 2,
        SETTING_CAPABILITY        = UINT64_C(1) << 3,
        SETTING_KILL_SIGNAL       = UINT64_C(1) << 4,
        SETTING_PERSONALITY       = UINT64_C(1) << 5,
        SETTING_MACHINE_ID        = UINT64_C(1) << 6,
        SETTING_NETWORK           = UINT64_C(1) << 7,
        SETTING_EXPOSE_PORTS      = UINT64_C(1) << 8,
        SETTING_READ_ONLY         = UINT64_C(1) << 9,
        SETTING_VOLATILE_MODE     = UINT64_C(1) << 10,
        SETTING_CUSTOM_MOUNTS     = UINT64_C(1) << 11,
        SETTING_WORKING_DIRECTORY = UINT64_C(1) << 12,
        SETTING_USERNS            = UINT64_C(1) << 13,
        SETTING_NOTIFY_READY      = UINT64_C(1) << 14,
        SETTING_PIVOT_ROOT        = UINT64_C(1) << 15,
        SETTING_SYSCALL_FILTER    = UINT64_C(1) << 16,
        SETTING_HOSTNAME          = UINT64_C(1) << 17,
        SETTING_NO_NEW_PRIVILEGES = UINT64_C(1) << 18,
        SETTING_OOM_SCORE_ADJUST  = UINT64_C(1) << 19,
        SETTING_CPU_AFFINITY      = UINT64_C(1) << 20,
        SETTING_RESOLV_CONF       = UINT64_C(1) << 21,
        SETTING_LINK_JOURNAL      = UINT64_C(1) << 22,
        SETTING_TIMEZONE          = UINT64_C(1) << 23,
        SETTING_EPHEMERAL         = UINT64_C(1) << 24,
        SETTING_SLICE             = UINT64_C(1) << 25,
        SETTING_DIRECTORY         = UINT64_C(1) << 26,
        SETTING_USE_CGNS          = UINT64_C(1) << 27,
        SETTING_CLONE_NS_FLAGS    = UINT64_C(1) << 28,
        SETTING_CONSOLE_MODE      = UINT64_C(1) << 29,
        SETTING_CREDENTIALS       = UINT64_C(1) << 30,
        SETTING_BIND_USER         = UINT64_C(1) << 31,
        SETTING_SUPPRESS_SYNC     = UINT64_C(1) << 32,
        SETTING_RLIMIT_FIRST      = UINT64_C(1) << 33, /* we define one bit per resource limit here */
        SETTING_RLIMIT_LAST       = UINT64_C(1) << (33 + _RLIMIT_MAX - 1),
        _SETTINGS_MASK_ALL        = (UINT64_C(1) << (33 + _RLIMIT_MAX)) -1,
        _SETTING_FORCE_ENUM_WIDTH = UINT64_MAX
} SettingsMask;

/* We want to use SETTING_RLIMIT_FIRST in shifts, so make sure it is really 64 bits
 * when used in expressions. */
#define SETTING_RLIMIT_FIRST ((uint64_t) SETTING_RLIMIT_FIRST)
#define SETTING_RLIMIT_LAST ((uint64_t) SETTING_RLIMIT_LAST)

assert_cc(sizeof(SettingsMask) == 8);
assert_cc(sizeof(SETTING_RLIMIT_FIRST) == 8);
assert_cc(sizeof(SETTING_RLIMIT_LAST) == 8);

typedef struct DeviceNode {
        char *path;
        unsigned major;
        unsigned minor;
        mode_t mode;
        uid_t uid;
        gid_t gid;
} DeviceNode;

typedef struct OciHook {
        char *path;
        char **args;
        char **env;
        usec_t timeout;
} OciHook;

typedef struct Settings {
        /* [Exec] */
        StartMode start_mode;
        int ephemeral;
        char **parameters;
        char **environment;
        char *user;
        uint64_t capability;
        uint64_t drop_capability;
        uint64_t ambient_capability;
        int kill_signal;
        unsigned long personality;
        sd_id128_t machine_id;
        char *working_directory;
        char *pivot_root_new;
        char *pivot_root_old;
        UserNamespaceMode userns_mode;
        uid_t uid_shift, uid_range;
        int notify_ready;
        char **syscall_allow_list;
        char **syscall_deny_list;
        struct rlimit *rlimit[_RLIMIT_MAX];
        char *hostname;
        int no_new_privileges;
        int oom_score_adjust;
        bool oom_score_adjust_set;
        CPUSet cpu_set;
        ResolvConfMode resolv_conf;
        LinkJournal link_journal;
        bool link_journal_try;
        TimezoneMode timezone;
        int suppress_sync;

        /* [Files] */
        int read_only;
        VolatileMode volatile_mode;
        CustomMount *custom_mounts;
        size_t n_custom_mounts;
        UserNamespaceOwnership userns_ownership;
        char **bind_user;

        /* [Network] */
        int private_network;
        int network_veth;
        char *network_bridge;
        char *network_zone;
        char **network_interfaces;
        char **network_macvlan;
        char **network_ipvlan;
        char **network_veth_extra;
        ExposePort *expose_ports;

        /* Additional fields, that are specific to OCI runtime case */
        char *bundle;
        char *root;
        OciHook *oci_hooks_prestart, *oci_hooks_poststart, *oci_hooks_poststop;
        size_t n_oci_hooks_prestart, n_oci_hooks_poststart, n_oci_hooks_poststop;
        char *slice;
        sd_bus_message *properties;
        CapabilityQuintet full_capabilities;
        uid_t uid;
        gid_t gid;
        gid_t *supplementary_gids;
        size_t n_supplementary_gids;
        unsigned console_width, console_height;
        ConsoleMode console_mode;
        DeviceNode *extra_nodes;
        size_t n_extra_nodes;
        unsigned long clone_ns_flags;
        char *network_namespace_path;
        int use_cgns;
        char **sysctl;
#if HAVE_SECCOMP
        scmp_filter_ctx seccomp;
#endif
} Settings;

Settings *settings_new(void);
int settings_load(FILE *f, const char *path, Settings **ret);
Settings* settings_free(Settings *s);

bool settings_network_veth(Settings *s);
bool settings_private_network(Settings *s);
bool settings_network_configured(Settings *s);

int settings_allocate_properties(Settings *s);

DEFINE_TRIVIAL_CLEANUP_FUNC(Settings*, settings_free);

const struct ConfigPerfItem* nspawn_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_capability);
CONFIG_PARSER_PROTOTYPE(config_parse_expose_port);
CONFIG_PARSER_PROTOTYPE(config_parse_volatile_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_pivot_root);
CONFIG_PARSER_PROTOTYPE(config_parse_bind);
CONFIG_PARSER_PROTOTYPE(config_parse_tmpfs);
CONFIG_PARSER_PROTOTYPE(config_parse_overlay);
CONFIG_PARSER_PROTOTYPE(config_parse_inaccessible);
CONFIG_PARSER_PROTOTYPE(config_parse_veth_extra);
CONFIG_PARSER_PROTOTYPE(config_parse_network_zone);
CONFIG_PARSER_PROTOTYPE(config_parse_boot);
CONFIG_PARSER_PROTOTYPE(config_parse_pid2);
CONFIG_PARSER_PROTOTYPE(config_parse_private_users);
CONFIG_PARSER_PROTOTYPE(config_parse_syscall_filter);
CONFIG_PARSER_PROTOTYPE(config_parse_oom_score_adjust);
CONFIG_PARSER_PROTOTYPE(config_parse_cpu_affinity);
CONFIG_PARSER_PROTOTYPE(config_parse_resolv_conf);
CONFIG_PARSER_PROTOTYPE(config_parse_link_journal);
CONFIG_PARSER_PROTOTYPE(config_parse_timezone);
CONFIG_PARSER_PROTOTYPE(config_parse_userns_chown);
CONFIG_PARSER_PROTOTYPE(config_parse_userns_ownership);
CONFIG_PARSER_PROTOTYPE(config_parse_bind_user);

const char *resolv_conf_mode_to_string(ResolvConfMode a) _const_;
ResolvConfMode resolv_conf_mode_from_string(const char *s) _pure_;

const char *timezone_mode_to_string(TimezoneMode a) _const_;
TimezoneMode timezone_mode_from_string(const char *s) _pure_;

const char *user_namespace_ownership_to_string(UserNamespaceOwnership a) _const_;
UserNamespaceOwnership user_namespace_ownership_from_string(const char *s) _pure_;

int parse_link_journal(const char *s, LinkJournal *ret_mode, bool *ret_try);

void device_node_array_free(DeviceNode *node, size_t n);
