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

#include "alloc-util.h"
#include "cap-list.h"
#include "conf-parser.h"
#include "nspawn-network.h"
#include "nspawn-settings.h"
#include "parse-util.h"
#include "process-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"
#include "string-util.h"

int settings_load(FILE *f, const char *path, Settings **ret) {
        _cleanup_(settings_freep) Settings *s = NULL;
        int r;

        assert(path);
        assert(ret);

        s = new0(Settings, 1);
        if (!s)
                return -ENOMEM;

        s->start_mode = _START_MODE_INVALID;
        s->personality = PERSONALITY_INVALID;
        s->userns_mode = _USER_NAMESPACE_MODE_INVALID;
        s->uid_shift = UID_INVALID;
        s->uid_range = UID_INVALID;

        s->read_only = -1;
        s->volatile_mode = _VOLATILE_MODE_INVALID;
        s->userns_chown = -1;

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

        /* Make sure that if userns_mode is set, userns_chown is set to something appropriate, and vice versa. Either
         * both fields shall be initialized or neither. */
        if (s->userns_mode == USER_NAMESPACE_PICK)
                s->userns_chown = true;
        else if (s->userns_mode != _USER_NAMESPACE_MODE_INVALID && s->userns_chown < 0)
                s->userns_chown = false;

        if (s->userns_chown >= 0 && s->userns_mode == _USER_NAMESPACE_MODE_INVALID)
                s->userns_mode = USER_NAMESPACE_NO;

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
        free(s->working_directory);

        strv_free(s->network_interfaces);
        strv_free(s->network_macvlan);
        strv_free(s->network_ipvlan);
        strv_free(s->network_veth_extra);
        free(s->network_bridge);
        expose_port_free_all(s->expose_ports);

        custom_mount_free_all(s->custom_mounts, s->n_custom_mounts);
        free(s);

        return NULL;
}

bool settings_private_network(Settings *s) {
        assert(s);

        return
                s->private_network > 0 ||
                s->network_veth > 0 ||
                s->network_bridge ||
                s->network_interfaces ||
                s->network_macvlan ||
                s->network_ipvlan ||
                s->network_veth_extra;
}

bool settings_network_veth(Settings *s) {
        assert(s);

        return
                s->network_veth > 0 ||
                s->network_bridge;
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
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse capability, ignoring: %s", word);
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

        return 0;
}

int config_parse_veth_extra(
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

        r = veth_extra_parse(&settings->network_veth_extra, rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid extra virtual Ethernet link specification %s: %m", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_boot(
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

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse Boot= parameter %s, ignoring: %m", rvalue);
                return 0;
        }

        if (r > 0) {
                if (settings->start_mode == START_PID2)
                        goto conflict;

                settings->start_mode = START_BOOT;
        } else {
                if (settings->start_mode == START_BOOT)
                        goto conflict;

                if (settings->start_mode < 0)
                        settings->start_mode = START_PID1;
        }

        return 0;

conflict:
        log_syntax(unit, LOG_ERR, filename, line, r, "Conflicting Boot= or ProcessTwo= setting found. Ignoring.");
        return 0;
}

int config_parse_pid2(
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

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse ProcessTwo= parameter %s, ignoring: %m", rvalue);
                return 0;
        }

        if (r > 0) {
                if (settings->start_mode == START_BOOT)
                        goto conflict;

                settings->start_mode = START_PID2;
        } else {
                if (settings->start_mode == START_PID2)
                        goto conflict;

                if (settings->start_mode < 0)
                        settings->start_mode = START_PID1;
        }

        return 0;

conflict:
        log_syntax(unit, LOG_ERR, filename, line, r, "Conflicting Boot= or ProcessTwo= setting found. Ignoring.");
        return 0;
}

int config_parse_private_users(
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

        r = parse_boolean(rvalue);
        if (r == 0) {
                /* no: User namespacing off */
                settings->userns_mode = USER_NAMESPACE_NO;
                settings->uid_shift = UID_INVALID;
                settings->uid_range = UINT32_C(0x10000);
        } else if (r > 0) {
                /* yes: User namespacing on, UID range is read from root dir */
                settings->userns_mode = USER_NAMESPACE_FIXED;
                settings->uid_shift = UID_INVALID;
                settings->uid_range = UINT32_C(0x10000);
        } else if (streq(rvalue, "pick")) {
                /* pick: User namespacing on, UID range is picked randomly */
                settings->userns_mode = USER_NAMESPACE_PICK;
                settings->uid_shift = UID_INVALID;
                settings->uid_range = UINT32_C(0x10000);
        } else {
                const char *range, *shift;
                uid_t sh, rn;

                /* anything else: User namespacing on, UID range is explicitly configured */

                range = strchr(rvalue, ':');
                if (range) {
                        shift = strndupa(rvalue, range - rvalue);
                        range++;

                        r = safe_atou32(range, &rn);
                        if (r < 0 || rn <= 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "UID/GID range invalid, ignoring: %s", range);
                                return 0;
                        }
                } else {
                        shift = rvalue;
                        rn = UINT32_C(0x10000);
                }

                r = parse_uid(shift, &sh);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "UID/GID shift invalid, ignoring: %s", range);
                        return 0;
                }

                settings->userns_mode = USER_NAMESPACE_FIXED;
                settings->uid_shift = sh;
                settings->uid_range = rn;
        }

        return 0;
}
