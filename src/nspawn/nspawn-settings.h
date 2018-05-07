/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering
***/

#include <stdio.h>

#include "sd-id128.h"

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
        SETTING_RLIMIT_FIRST      = UINT64_C(1) << 17, /* we define one bit per resource limit here */
        SETTING_RLIMIT_LAST       = UINT64_C(1) << (17 + _RLIMIT_MAX - 1),
        _SETTINGS_MASK_ALL        = (UINT64_C(1) << (17 + _RLIMIT_MAX))
} SettingsMask;

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

int config_parse_capability(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_id128(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_expose_port(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_volatile_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_pivot_root(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bind(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_tmpfs(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_overlay(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_veth_extra(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_network_zone(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_boot(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_pid2(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_private_users(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_syscall_filter(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
