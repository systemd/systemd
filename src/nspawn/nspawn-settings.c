/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "util.h"
#include "conf-parser.h"
#include "strv.h"
#include "cap-list.h"

#include "nspawn-settings.h"

int settings_load(FILE *f, const char *path, Settings **ret) {
        _cleanup_(settings_freep) Settings *s = NULL;
        int r;

        assert(path);
        assert(ret);

        s = new0(Settings, 1);
        if (!s)
                return -ENOMEM;

        s->boot = -1;
        s->personality = PERSONALITY_INVALID;

        s->read_only = -1;
        s->volatile_mode = _VOLATILE_MODE_INVALID;

        s->private_network = -1;
        s->network_veth = -1;

        r = config_parse(NULL, path, f,
                         "Exec\0"
                         "Network\0"
                         "Files\0",
                         config_item_perf_lookup, nspawn_gperf_lookup,
                         false,
                         false,
                         true,
                         s);
        if (r < 0)
                return r;

        *ret = s;
        s = NULL;

        return 0;
}

Settings* settings_free(Settings *s) {

        if (!s)
                return NULL;

        strv_free(s->parameters);
        strv_free(s->environment);
        free(s->user);

        strv_free(s->network_interfaces);
        strv_free(s->network_macvlan);
        strv_free(s->network_ipvlan);
        free(s->network_bridge);
        expose_port_free_all(s->expose_ports);

        custom_mount_free_all(s->custom_mounts, s->n_custom_mounts);
        free(s);

        return NULL;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_volatile_mode, volatile_mode, VolatileMode, "Failed to parse volatile mode");

int config_parse_expose_port(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Settings *s = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = expose_port_parse(&s->expose_ports, rvalue);
        if (r == -EEXIST) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Duplicate port specification, ignoring: %s", rvalue);
                return 0;
        }
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse host port %s: %m", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_capability(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t u = 0, *result = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                int cap;

                r = extract_first_word(&rvalue, &word, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract capability string, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                cap = capability_from_name(word);
                if (cap < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, cap, "Failed to parse capability, ignoring: %s", word);
                        continue;
                }

                u |= 1 << ((uint64_t) cap);
        }

        if (u == 0)
                return 0;

        *result |= u;
        return 0;
}

int config_parse_id128(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        sd_id128_t t, *result = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = sd_id128_from_string(rvalue, &t);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse 128bit ID/UUID, ignoring: %s", rvalue);
                return 0;
        }

        *result = t;
        return 0;
}

int config_parse_bind(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Settings *settings = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = bind_mount_parse(&settings->custom_mounts, &settings->n_custom_mounts, rvalue, ltype);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid bind mount specification %s: %m", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_tmpfs(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Settings *settings = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tmpfs_mount_parse(&settings->custom_mounts, &settings->n_custom_mounts, rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid temporary file system specification %s: %m", rvalue);
                return 0;
        }

        if (settings->network_bridge)
                settings->network_veth = true;

        if (settings->network_interfaces ||
            settings->network_macvlan ||
            settings->network_ipvlan ||
            settings->network_bridge ||
            settings->network_veth)
                settings->private_network = true;

        return 0;
}
