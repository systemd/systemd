/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <stdio.h>

#include "macro.h"

#include "nspawn-mount.h"
#include "nspawn-expose-ports.h"

typedef enum SettingsMask {
        SETTING_BOOT          = 1 << 0,
        SETTING_ENVIRONMENT   = 1 << 1,
        SETTING_USER          = 1 << 2,
        SETTING_CAPABILITY    = 1 << 3,
        SETTING_KILL_SIGNAL   = 1 << 4,
        SETTING_PERSONALITY   = 1 << 5,
        SETTING_MACHINE_ID    = 1 << 6,
        SETTING_NETWORK       = 1 << 7,
        SETTING_EXPOSE_PORTS  = 1 << 8,
        SETTING_READ_ONLY     = 1 << 9,
        SETTING_VOLATILE_MODE = 1 << 10,
        SETTING_CUSTOM_MOUNTS = 1 << 11,
        _SETTINGS_MASK_ALL    = (1 << 12) -1
} SettingsMask;

typedef struct Settings {
        /* [Run] */
        int boot;
        char **parameters;
        char **environment;
        char *user;
        uint64_t capability;
        uint64_t drop_capability;
        int kill_signal;
        unsigned long personality;
        sd_id128_t machine_id;

        /* [Image] */
        int read_only;
        VolatileMode volatile_mode;
        CustomMount *custom_mounts;
        unsigned n_custom_mounts;

        /* [Network] */
        int private_network;
        int network_veth;
        char *network_bridge;
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

const struct ConfigPerfItem* nspawn_gperf_lookup(const char *key, unsigned length);

int config_parse_capability(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_id128(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_expose_port(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_volatile_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bind(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_tmpfs(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_veth_extra(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
