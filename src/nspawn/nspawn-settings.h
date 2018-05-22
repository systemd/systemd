/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering
***/

#include <sched.h>
#include <stdio.h>

#include "sd-id128.h"

#include "conf-parser.h"
#include "macro.h"
#include "nspawn-expose-ports.h"
#include "nspawn-mount.h"

typedef enum StartMode {
        START_PID1, /* Run parameters as command line as process 1 */
        START_PID2, /* Use stub init process as PID 1, run parameters as command line as process 2 */
        START_BOOT, /* Search for init system, pass arguments as parameters */
        _START_MODE_MAX,
        _START_MODE_INVALID = -1
} StartMode;

typedef enum UserNamespaceMode {
        USER_NAMESPACE_NO,
        USER_NAMESPACE_FIXED,
        USER_NAMESPACE_PICK,
        _USER_NAMESPACE_MODE_MAX,
        _USER_NAMESPACE_MODE_INVALID = -1,
} UserNamespaceMode;

#define SETTING_START_MODE              (1L << 0)
#define SETTING_ENVIRONMENT             (1L << 1)
#define SETTING_USER                    (1L << 2)
#define SETTING_CAPABILITY              (1L << 3)
#define SETTING_KILL_SIGNAL             (1L << 4)
#define SETTING_PERSONALITY             (1L << 5)
#define SETTING_MACHINE_ID              (1L << 6)
#define SETTING_NETWORK                 (1L << 7)
#define SETTING_EXPOSE_PORTS            (1L << 8)
#define SETTING_READ_ONLY               (1L << 9)
#define SETTING_VOLATILE_MODE           (1L << 10)
#define SETTING_CUSTOM_MOUNTS           (1L << 11)
#define SETTING_WORKING_DIRECTORY       (1L << 12)
#define SETTING_USERNS                  (1L << 13)
#define SETTING_NOTIFY_READY            (1L << 14)
#define SETTING_PIVOT_ROOT              (1L << 15)
#define SETTING_SYSCALL_FILTER          (1L << 16)
#define SETTING_HOSTNAME                (1L << 17)
#define SETTING_NO_NEW_PRIVILEGES       (1L << 18)
#define SETTING_OOM_SCORE_ADJUST        (1L << 19)
#define SETTING_CPU_AFFINITY            (1L << 20)
/* we define one bit per resource limit here */
#define SETTING_RLIMIT_FIRST            (1L << 21)
#define SETTING_RLIMIT_LAST             (1L << (21 + _RLIMIT_MAX - 1))
#define _SETTINGS_MASK_ALL              ((1L << (21 + _RLIMIT_MAX)) - 1)
typedef uint64_t SettingsMask;

assert_cc(sizeof(SettingsMask) == 8);
assert_cc(sizeof(SETTING_RLIMIT_FIRST) == 8);
assert_cc(sizeof(SETTING_RLIMIT_LAST) == 8);

typedef struct Settings {
        /* [Run] */
        StartMode start_mode;
        char **parameters;
        char **environment;
        char *user;
        uint64_t capability;
        uint64_t drop_capability;
        int kill_signal;
        unsigned long personality;
        sd_id128_t machine_id;
        char *working_directory;
        char *pivot_root_new;
        char *pivot_root_old;
        UserNamespaceMode userns_mode;
        uid_t uid_shift, uid_range;
        bool notify_ready;
        char **syscall_whitelist;
        char **syscall_blacklist;
        struct rlimit *rlimit[_RLIMIT_MAX];
        char *hostname;
        int no_new_privileges;
        int oom_score_adjust;
        bool oom_score_adjust_set;
        cpu_set_t *cpuset;
        unsigned cpuset_ncpus;

        /* [Image] */
        int read_only;
        VolatileMode volatile_mode;
        CustomMount *custom_mounts;
        size_t n_custom_mounts;
        int userns_chown;

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
} Settings;

int settings_load(FILE *f, const char *path, Settings **ret);
Settings* settings_free(Settings *s);

bool settings_network_veth(Settings *s);
bool settings_private_network(Settings *s);

DEFINE_TRIVIAL_CLEANUP_FUNC(Settings*, settings_free);

const struct ConfigPerfItem* nspawn_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_capability);
CONFIG_PARSER_PROTOTYPE(config_parse_id128);
CONFIG_PARSER_PROTOTYPE(config_parse_expose_port);
CONFIG_PARSER_PROTOTYPE(config_parse_volatile_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_pivot_root);
CONFIG_PARSER_PROTOTYPE(config_parse_bind);
CONFIG_PARSER_PROTOTYPE(config_parse_tmpfs);
CONFIG_PARSER_PROTOTYPE(config_parse_overlay);
CONFIG_PARSER_PROTOTYPE(config_parse_veth_extra);
CONFIG_PARSER_PROTOTYPE(config_parse_network_zone);
CONFIG_PARSER_PROTOTYPE(config_parse_boot);
CONFIG_PARSER_PROTOTYPE(config_parse_pid2);
CONFIG_PARSER_PROTOTYPE(config_parse_private_users);
CONFIG_PARSER_PROTOTYPE(config_parse_syscall_filter);
CONFIG_PARSER_PROTOTYPE(config_parse_hostname);
CONFIG_PARSER_PROTOTYPE(config_parse_oom_score_adjust);
CONFIG_PARSER_PROTOTYPE(config_parse_cpu_affinity);
