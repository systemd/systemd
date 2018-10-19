/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "cap-list.h"
#include "conf-parser.h"
#include "cpu-set-util.h"
#include "hostname-util.h"
#include "nspawn-network.h"
#include "nspawn-settings.h"
#include "parse-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

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
        s->resolv_conf = _RESOLV_CONF_MODE_INVALID;
        s->link_journal = _LINK_JOURNAL_INVALID;
        s->timezone = _TIMEZONE_MODE_INVALID;
        s->uid_shift = UID_INVALID;
        s->uid_range = UID_INVALID;
        s->no_new_privileges = -1;

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
                         CONFIG_PARSE_WARN,
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

        *ret = TAKE_PTR(s);

        return 0;
}

Settings* settings_free(Settings *s) {

        if (!s)
                return NULL;

        strv_free(s->parameters);
        strv_free(s->environment);
        free(s->user);
        free(s->pivot_root_new);
        free(s->pivot_root_old);
        free(s->working_directory);
        strv_free(s->syscall_whitelist);
        strv_free(s->syscall_blacklist);
        rlimit_free_all(s->rlimit);
        free(s->hostname);
        s->cpuset = cpu_set_mfree(s->cpuset);

        strv_free(s->network_interfaces);
        strv_free(s->network_macvlan);
        strv_free(s->network_ipvlan);
        strv_free(s->network_veth_extra);
        free(s->network_bridge);
        free(s->network_zone);
        expose_port_free_all(s->expose_ports);

        custom_mount_free_all(s->custom_mounts, s->n_custom_mounts);
        return mfree(s);
}

bool settings_private_network(Settings *s) {
        assert(s);

        return
                s->private_network > 0 ||
                s->network_veth > 0 ||
                s->network_bridge ||
                s->network_zone ||
                s->network_interfaces ||
                s->network_macvlan ||
                s->network_ipvlan ||
                s->network_veth_extra;
}

bool settings_network_veth(Settings *s) {
        assert(s);

        return
                s->network_veth > 0 ||
                s->network_bridge ||
                s->network_zone;
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

                u |= UINT64_C(1) << cap;
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

int config_parse_pivot_root(
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

        r = pivot_root_parse(&settings->pivot_root_new, &settings->pivot_root_old, rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid pivot root mount specification %s: %m", rvalue);
                return 0;
        }

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

int config_parse_overlay(
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

        r = overlay_mount_parse(&settings->custom_mounts, &settings->n_custom_mounts, rvalue, ltype);
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid overlay file system specification %s, ignoring: %m", rvalue);

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

int config_parse_network_zone(
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
        _cleanup_free_ char *j = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        j = strappend("vz-", rvalue);
        if (!ifname_valid(j)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid network zone name, ignoring: %s", rvalue);
                return 0;
        }

        free_and_replace(settings->network_zone, j);

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

int config_parse_syscall_filter(
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
        bool negative;
        const char *items;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        negative = rvalue[0] == '~';
        items = negative ? rvalue + 1 : rvalue;

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&items, &word, NULL, 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse SystemCallFilter= parameter %s, ignoring: %m", rvalue);
                        return 0;
                }

                if (negative)
                        r = strv_extend(&settings->syscall_blacklist, word);
                else
                        r = strv_extend(&settings->syscall_whitelist, word);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

int config_parse_hostname(
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

        char **s = data;

        assert(rvalue);
        assert(s);

        if (!hostname_is_valid(rvalue, false)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid hostname, ignoring: %s", rvalue);
                return 0;
        }

        if (free_and_strdup(s, empty_to_null(rvalue)) < 0)
                return log_oom();

        return 0;
}

int config_parse_oom_score_adjust(
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
        int oa, r;

        assert(rvalue);
        assert(settings);

        if (isempty(rvalue)) {
                settings->oom_score_adjust_set = false;
                return 0;
        }

        r = parse_oom_score_adjust(rvalue, &oa);
        if (r == -ERANGE) {
                log_syntax(unit, LOG_ERR, filename, line, r, "OOM score adjust value out of range, ignoring: %s", rvalue);
                return 0;
        }
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse the OOM score adjust value, ignoring: %s", rvalue);
                return 0;
        }

        settings->oom_score_adjust = oa;
        settings->oom_score_adjust_set = true;

        return 0;
}

int config_parse_cpu_affinity(
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

        _cleanup_cpu_free_ cpu_set_t *cpuset = NULL;
        Settings *settings = data;
        int ncpus;

        assert(rvalue);
        assert(settings);

        ncpus = parse_cpu_set_and_warn(rvalue, &cpuset, unit, filename, line, lvalue);
        if (ncpus < 0)
                return ncpus;

        if (ncpus == 0) {
                /* An empty assignment resets the CPU list */
                settings->cpuset = cpu_set_mfree(settings->cpuset);
                settings->cpuset_ncpus = 0;
                return 0;
        }

        if (!settings->cpuset) {
                settings->cpuset = TAKE_PTR(cpuset);
                settings->cpuset_ncpus = (unsigned) ncpus;
                return 0;
        }

        if (settings->cpuset_ncpus < (unsigned) ncpus) {
                CPU_OR_S(CPU_ALLOC_SIZE(settings->cpuset_ncpus), cpuset, settings->cpuset, cpuset);
                CPU_FREE(settings->cpuset);
                settings->cpuset = TAKE_PTR(cpuset);
                settings->cpuset_ncpus = (unsigned) ncpus;
                return 0;
        }

        CPU_OR_S(CPU_ALLOC_SIZE((unsigned) ncpus), settings->cpuset, settings->cpuset, cpuset);

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_resolv_conf, resolv_conf_mode, ResolvConfMode, "Failed to parse resolv.conf mode");

static const char *const resolv_conf_mode_table[_RESOLV_CONF_MODE_MAX] = {
        [RESOLV_CONF_OFF] = "off",
        [RESOLV_CONF_COPY_HOST] = "copy-host",
        [RESOLV_CONF_COPY_STATIC] = "copy-static",
        [RESOLV_CONF_BIND_HOST] = "bind-host",
        [RESOLV_CONF_BIND_STATIC] = "bind-static",
        [RESOLV_CONF_DELETE] = "delete",
        [RESOLV_CONF_AUTO] = "auto",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(resolv_conf_mode, ResolvConfMode, RESOLV_CONF_AUTO);

int parse_link_journal(const char *s, LinkJournal *ret_mode, bool *ret_try) {
        assert(s);
        assert(ret_mode);
        assert(ret_try);

        if (streq(s, "auto")) {
                *ret_mode = LINK_AUTO;
                *ret_try = false;
        } else if (streq(s, "no")) {
                *ret_mode = LINK_NO;
                *ret_try = false;
        } else if (streq(s, "guest")) {
                *ret_mode = LINK_GUEST;
                *ret_try = false;
        } else if (streq(s, "host")) {
                *ret_mode = LINK_HOST;
                *ret_try = false;
        } else if (streq(s, "try-guest")) {
                *ret_mode = LINK_GUEST;
                *ret_try = true;
        } else if (streq(s, "try-host")) {
                *ret_mode = LINK_HOST;
                *ret_try = true;
        } else
                return -EINVAL;

        return 0;
}

int config_parse_link_journal(
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

        assert(rvalue);
        assert(settings);

        r = parse_link_journal(rvalue, &settings->link_journal, &settings->link_journal_try);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse link journal mode, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_timezone, timezone_mode, TimezoneMode, "Failed to parse timezone mode");

static const char *const timezone_mode_table[_TIMEZONE_MODE_MAX] = {
        [TIMEZONE_OFF] = "off",
        [TIMEZONE_COPY] = "copy",
        [TIMEZONE_BIND] = "bind",
        [TIMEZONE_SYMLINK] = "symlink",
        [TIMEZONE_DELETE] = "delete",
        [TIMEZONE_AUTO] = "auto",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(timezone_mode, TimezoneMode, TIMEZONE_AUTO);
