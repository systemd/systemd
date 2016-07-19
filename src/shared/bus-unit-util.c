/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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
#include "bus-internal.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "env-util.h"
#include "escape.h"
#include "hashmap.h"
#include "list.h"
#include "locale-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "utf8.h"
#include "util.h"

int bus_parse_unit_info(sd_bus_message *message, UnitInfo *u) {
        assert(message);
        assert(u);

        u->machine = NULL;

        return sd_bus_message_read(
                        message,
                        "(ssssssouso)",
                        &u->id,
                        &u->description,
                        &u->load_state,
                        &u->active_state,
                        &u->sub_state,
                        &u->following,
                        &u->unit_path,
                        &u->job_id,
                        &u->job_type,
                        &u->job_path);
}

int bus_append_unit_property_assignment(sd_bus_message *m, const char *assignment) {
        const char *eq, *field;
        int r, rl;

        assert(m);
        assert(assignment);

        eq = strchr(assignment, '=');
        if (!eq) {
                log_error("Not an assignment: %s", assignment);
                return -EINVAL;
        }

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
        if (r < 0)
                return bus_log_create_error(r);

        field = strndupa(assignment, eq - assignment);
        eq++;

        if (streq(field, "CPUQuota")) {

                if (isempty(eq))
                        r = sd_bus_message_append(m, "sv", "CPUQuotaPerSecUSec", "t", USEC_INFINITY);
                else {
                        r = parse_percent(eq);
                        if (r <= 0) {
                                log_error_errno(r, "CPU quota '%s' invalid.", eq);
                                return -EINVAL;
                        }

                        r = sd_bus_message_append(m, "sv", "CPUQuotaPerSecUSec", "t", (usec_t) r * USEC_PER_SEC / 100U);
                }

                goto finish;

        } else if (streq(field, "EnvironmentFile")) {

                r = sd_bus_message_append(m, "sv", "EnvironmentFiles", "a(sb)", 1,
                                          eq[0] == '-' ? eq + 1 : eq,
                                          eq[0] == '-');
                goto finish;

        } else if (STR_IN_SET(field, "AccuracySec", "RandomizedDelaySec", "RuntimeMaxSec")) {
                char *n;
                usec_t t;
                size_t l;

                r = parse_sec(eq, &t);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s= parameter: %s", field, eq);

                l = strlen(field);
                n = newa(char, l + 2);
                if (!n)
                        return log_oom();

                /* Change suffix Sec → USec */
                strcpy(mempcpy(n, field, l - 3), "USec");
                r = sd_bus_message_append(m, "sv", n, "t", t);
                goto finish;

        } else if (STR_IN_SET(field, "MemoryLow", "MemoryHigh", "MemoryMax", "MemoryLimit")) {
                uint64_t bytes;

                if (isempty(eq) || streq(eq, "infinity"))
                        bytes = CGROUP_LIMIT_MAX;
                else {
                        r = parse_percent(eq);
                        if (r >= 0) {
                                char *n;

                                /* When this is a percentage we'll convert this into a relative value in the range
                                 * 0…UINT32_MAX and pass it in the MemoryLowByPhysicalMemory property (and related
                                 * ones). This way the physical memory size can be determined server-side */

                                n = strjoina(field, "ByPhysicalMemory");
                                r = sd_bus_message_append(m, "sv", n, "u", (uint32_t) (((uint64_t) UINT32_MAX * r) / 100U));
                                goto finish;

                        } else {
                                r = parse_size(eq, 1024, &bytes);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse bytes specification %s", assignment);
                        }
                }

                r = sd_bus_message_append(m, "sv", field, "t", bytes);
                goto finish;
        }

        r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
        if (r < 0)
                return bus_log_create_error(r);

        rl = rlimit_from_string(field);
        if (rl >= 0) {
                const char *sn;
                struct rlimit l;

                r = rlimit_parse(rl, eq, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse resource limit: %s", eq);

                r = sd_bus_message_append(m, "v", "t", l.rlim_max);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "sv");
                if (r < 0)
                        return bus_log_create_error(r);

                sn = strjoina(field, "Soft");
                r = sd_bus_message_append(m, "sv", sn, "t", l.rlim_cur);

        } else if (STR_IN_SET(field,
                       "CPUAccounting", "MemoryAccounting", "IOAccounting", "BlockIOAccounting", "TasksAccounting",
                       "SendSIGHUP", "SendSIGKILL", "WakeSystem", "DefaultDependencies",
                       "IgnoreSIGPIPE", "TTYVHangup", "TTYReset", "RemainAfterExit",
                       "PrivateTmp", "PrivateDevices", "PrivateNetwork", "NoNewPrivileges",
                       "SyslogLevelPrefix", "Delegate", "RemainAfterElapse", "MemoryDenyWriteExecute")) {

                r = parse_boolean(eq);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse boolean assignment %s.", assignment);

                r = sd_bus_message_append(m, "v", "b", r);

        } else if (streq(field, "TasksMax")) {
                uint64_t n;

                if (isempty(eq) || streq(eq, "infinity"))
                        n = (uint64_t) -1;
                else {
                        r = safe_atou64(eq, &n);
                        if (r < 0) {
                                log_error("Failed to parse maximum tasks specification %s", assignment);
                                return -EINVAL;
                        }
                }

                r = sd_bus_message_append(m, "v", "t", n);

        } else if (STR_IN_SET(field, "CPUShares", "StartupCPUShares")) {
                uint64_t u;

                r = cg_cpu_shares_parse(eq, &u);
                if (r < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "t", u);

        } else if (STR_IN_SET(field, "IOWeight", "StartupIOWeight")) {
                uint64_t u;

                r = cg_weight_parse(eq, &u);
                if (r < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "t", u);

        } else if (STR_IN_SET(field, "BlockIOWeight", "StartupBlockIOWeight")) {
                uint64_t u;

                r = cg_blkio_weight_parse(eq, &u);
                if (r < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "t", u);

        } else if (STR_IN_SET(field,
                              "User", "Group", "DevicePolicy", "KillMode",
                              "UtmpIdentifier", "UtmpMode", "PAMName", "TTYPath",
                              "StandardInput", "StandardOutput", "StandardError",
                              "Description", "Slice", "Type", "WorkingDirectory",
                              "RootDirectory", "SyslogIdentifier", "ProtectSystem",
                              "ProtectHome", "SELinuxContext"))
                r = sd_bus_message_append(m, "v", "s", eq);

        else if (streq(field, "SyslogLevel")) {
                int level;

                level = log_level_from_string(eq);
                if (level < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "i", level);

        } else if (streq(field, "SyslogFacility")) {
                int facility;

                facility = log_facility_unshifted_from_string(eq);
                if (facility < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "i", facility);

        } else if (streq(field, "DeviceAllow")) {

                if (isempty(eq))
                        r = sd_bus_message_append(m, "v", "a(ss)", 0);
                else {
                        const char *path, *rwm, *e;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa(eq, e - eq);
                                rwm = e+1;
                        } else {
                                path = eq;
                                rwm = "";
                        }

                        if (!path_startswith(path, "/dev")) {
                                log_error("%s is not a device file in /dev.", path);
                                return -EINVAL;
                        }

                        r = sd_bus_message_append(m, "v", "a(ss)", 1, path, rwm);
                }

        } else if (cgroup_io_limit_type_from_string(field) >= 0 || STR_IN_SET(field, "BlockIOReadBandwidth", "BlockIOWriteBandwidth")) {

                if (isempty(eq))
                        r = sd_bus_message_append(m, "v", "a(st)", 0);
                else {
                        const char *path, *bandwidth, *e;
                        uint64_t bytes;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa(eq, e - eq);
                                bandwidth = e+1;
                        } else {
                                log_error("Failed to parse %s value %s.", field, eq);
                                return -EINVAL;
                        }

                        if (!path_startswith(path, "/dev")) {
                                log_error("%s is not a device file in /dev.", path);
                                return -EINVAL;
                        }

                        if (streq(bandwidth, "infinity")) {
                                bytes = CGROUP_LIMIT_MAX;
                        } else {
                                r = parse_size(bandwidth, 1000, &bytes);
                                if (r < 0) {
                                        log_error("Failed to parse byte value %s.", bandwidth);
                                        return -EINVAL;
                                }
                        }

                        r = sd_bus_message_append(m, "v", "a(st)", 1, path, bytes);
                }

        } else if (STR_IN_SET(field, "IODeviceWeight", "BlockIODeviceWeight")) {

                if (isempty(eq))
                        r = sd_bus_message_append(m, "v", "a(st)", 0);
                else {
                        const char *path, *weight, *e;
                        uint64_t u;

                        e = strchr(eq, ' ');
                        if (e) {
                                path = strndupa(eq, e - eq);
                                weight = e+1;
                        } else {
                                log_error("Failed to parse %s value %s.", field, eq);
                                return -EINVAL;
                        }

                        if (!path_startswith(path, "/dev")) {
                                log_error("%s is not a device file in /dev.", path);
                                return -EINVAL;
                        }

                        r = safe_atou64(weight, &u);
                        if (r < 0) {
                                log_error("Failed to parse %s value %s.", field, weight);
                                return -EINVAL;
                        }
                        r = sd_bus_message_append(m, "v", "a(st)", 1, path, u);
                }

        } else if (streq(field, "Nice")) {
                int32_t i;

                r = safe_atoi32(eq, &i);
                if (r < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "i", i);

        } else if (STR_IN_SET(field, "Environment", "PassEnvironment")) {
                const char *p;

                r = sd_bus_message_open_container(m, 'v', "as");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "s");
                if (r < 0)
                        return bus_log_create_error(r);

                p = eq;

                for (;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE);
                        if (r < 0) {
                                log_error("Failed to parse Environment value %s", eq);
                                return -EINVAL;
                        }
                        if (r == 0)
                                break;

                        if (streq(field, "Environment")) {
                                if (!env_assignment_is_valid(word)) {
                                        log_error("Invalid environment assignment: %s", word);
                                        return -EINVAL;
                                }
                        } else {  /* PassEnvironment */
                                if (!env_name_is_valid(word)) {
                                        log_error("Invalid environment variable name: %s", word);
                                        return -EINVAL;
                                }
                        }

                        r = sd_bus_message_append_basic(m, 's', word);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);

        } else if (streq(field, "KillSignal")) {
                int sig;

                sig = signal_from_string_try_harder(eq);
                if (sig < 0) {
                        log_error("Failed to parse %s value %s.", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "i", sig);

        } else if (streq(field, "TimerSlackNSec")) {
                nsec_t n;

                r = parse_nsec(eq, &n);
                if (r < 0) {
                        log_error("Failed to parse %s value %s", field, eq);
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "t", n);
        } else if (streq(field, "OOMScoreAdjust")) {
                int oa;

                r = safe_atoi(eq, &oa);
                if (r < 0) {
                        log_error("Failed to parse %s value %s", field, eq);
                        return -EINVAL;
                }

                if (!oom_score_adjust_is_valid(oa)) {
                        log_error("OOM score adjust value out of range");
                        return -EINVAL;
                }

                r = sd_bus_message_append(m, "v", "i", oa);
        } else if (STR_IN_SET(field, "ReadWriteDirectories", "ReadOnlyDirectories", "InaccessibleDirectories",
                              "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths")) {
                const char *p;

                r = sd_bus_message_open_container(m, 'v', "as");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "s");
                if (r < 0)
                        return bus_log_create_error(r);

                p = eq;

                for (;;) {
                        _cleanup_free_ char *word = NULL;
                        int offset;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                        if (r < 0) {
                                log_error("Failed to parse %s value %s", field, eq);
                                return -EINVAL;
                        }
                        if (r == 0)
                                break;

                        if (!utf8_is_valid(word)) {
                                log_error("Failed to parse %s value %s", field, eq);
                                return -EINVAL;
                        }

                        offset = word[0] == '-';
                        if (!path_is_absolute(word + offset)) {
                                log_error("Failed to parse %s value %s", field, eq);
                                return -EINVAL;
                        }

                        path_kill_slashes(word + offset);

                        r = sd_bus_message_append_basic(m, 's', word);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);

        } else if (streq(field, "RuntimeDirectory")) {
                const char *p;

                r = sd_bus_message_open_container(m, 'v', "as");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "s");
                if (r < 0)
                        return bus_log_create_error(r);

                p = eq;

                for (;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s value %s", field, eq);

                        if (r == 0)
                                break;

                        r = sd_bus_message_append_basic(m, 's', word);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);

        } else {
                log_error("Unknown assignment %s.", assignment);
                return -EINVAL;
        }

finish:
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

typedef struct BusWaitForJobs {
        sd_bus *bus;
        Set *jobs;

        char *name;
        char *result;

        sd_bus_slot *slot_job_removed;
        sd_bus_slot *slot_disconnected;
} BusWaitForJobs;

static int match_disconnected(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        assert(m);

        log_error("Warning! D-Bus connection terminated.");
        sd_bus_close(sd_bus_message_get_bus(m));

        return 0;
}

static int match_job_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char *path, *unit, *result;
        BusWaitForJobs *d = userdata;
        uint32_t id;
        char *found;
        int r;

        assert(m);
        assert(d);

        r = sd_bus_message_read(m, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        found = set_remove(d->jobs, (char*) path);
        if (!found)
                return 0;

        free(found);

        if (!isempty(result))
                d->result = strdup(result);

        if (!isempty(unit))
                d->name = strdup(unit);

        return 0;
}

void bus_wait_for_jobs_free(BusWaitForJobs *d) {
        if (!d)
                return;

        set_free_free(d->jobs);

        sd_bus_slot_unref(d->slot_disconnected);
        sd_bus_slot_unref(d->slot_job_removed);

        sd_bus_unref(d->bus);

        free(d->name);
        free(d->result);

        free(d);
}

int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *d = NULL;
        int r;

        assert(bus);
        assert(ret);

        d = new0(BusWaitForJobs, 1);
        if (!d)
                return -ENOMEM;

        d->bus = sd_bus_ref(bus);

        /* When we are a bus client we match by sender. Direct
         * connections OTOH have no initialized sender field, and
         * hence we ignore the sender then */
        r = sd_bus_add_match(
                        bus,
                        &d->slot_job_removed,
                        bus->bus_client ?
                        "type='signal',"
                        "sender='org.freedesktop.systemd1',"
                        "interface='org.freedesktop.systemd1.Manager',"
                        "member='JobRemoved',"
                        "path='/org/freedesktop/systemd1'" :
                        "type='signal',"
                        "interface='org.freedesktop.systemd1.Manager',"
                        "member='JobRemoved',"
                        "path='/org/freedesktop/systemd1'",
                        match_job_removed, d);
        if (r < 0)
                return r;

        r = sd_bus_add_match(
                        bus,
                        &d->slot_disconnected,
                        "type='signal',"
                        "sender='org.freedesktop.DBus.Local',"
                        "interface='org.freedesktop.DBus.Local',"
                        "member='Disconnected'",
                        match_disconnected, d);
        if (r < 0)
                return r;

        *ret = d;
        d = NULL;

        return 0;
}

static int bus_process_wait(sd_bus *bus) {
        int r;

        for (;;) {
                r = sd_bus_process(bus, NULL);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;

                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0)
                        return r;
        }
}

static int bus_job_get_service_result(BusWaitForJobs *d, char **result) {
        _cleanup_free_ char *dbus_path = NULL;

        assert(d);
        assert(d->name);
        assert(result);

        dbus_path = unit_dbus_path_from_name(d->name);
        if (!dbus_path)
                return -ENOMEM;

        return sd_bus_get_property_string(d->bus,
                                          "org.freedesktop.systemd1",
                                          dbus_path,
                                          "org.freedesktop.systemd1.Service",
                                          "Result",
                                          NULL,
                                          result);
}

static const struct {
        const char *result, *explanation;
} explanations [] = {
        { "resources",   "of unavailable resources or another system error" },
        { "timeout",     "a timeout was exceeded" },
        { "exit-code",   "the control process exited with error code" },
        { "signal",      "a fatal signal was delivered to the control process" },
        { "core-dump",   "a fatal signal was delivered causing the control process to dump core" },
        { "watchdog",    "the service failed to send watchdog ping" },
        { "start-limit", "start of the service was attempted too often" }
};

static void log_job_error_with_service_result(const char* service, const char *result, const char* const* extra_args) {
        _cleanup_free_ char *service_shell_quoted = NULL;
        const char *systemctl = "systemctl", *journalctl = "journalctl";

        assert(service);

        service_shell_quoted = shell_maybe_quote(service);

        if (extra_args && extra_args[1]) {
                _cleanup_free_ char *t;

                t = strv_join((char**) extra_args, " ");
                systemctl = strjoina("systemctl ", t ? : "<args>");
                journalctl = strjoina("journalctl ", t ? : "<args>");
        }

        if (!isempty(result)) {
                unsigned i;

                for (i = 0; i < ELEMENTSOF(explanations); ++i)
                        if (streq(result, explanations[i].result))
                                break;

                if (i < ELEMENTSOF(explanations)) {
                        log_error("Job for %s failed because %s.\n"
                                  "See \"%s status %s\" and \"%s -xe\" for details.\n",
                                  service,
                                  explanations[i].explanation,
                                  systemctl,
                                  service_shell_quoted ?: "<service>",
                                  journalctl);
                        goto finish;
                }
        }

        log_error("Job for %s failed.\n"
                  "See \"%s status %s\" and \"%s -xe\" for details.\n",
                  service,
                  systemctl,
                  service_shell_quoted ?: "<service>",
                  journalctl);

finish:
        /* For some results maybe additional explanation is required */
        if (streq_ptr(result, "start-limit"))
                log_info("To force a start use \"%1$s reset-failed %2$s\"\n"
                         "followed by \"%1$s start %2$s\" again.",
                         systemctl,
                         service_shell_quoted ?: "<service>");
}

static int check_wait_response(BusWaitForJobs *d, bool quiet, const char* const* extra_args) {
        int r = 0;

        assert(d->result);

        if (!quiet) {
                if (streq(d->result, "canceled"))
                        log_error("Job for %s canceled.", strna(d->name));
                else if (streq(d->result, "timeout"))
                        log_error("Job for %s timed out.", strna(d->name));
                else if (streq(d->result, "dependency"))
                        log_error("A dependency job for %s failed. See 'journalctl -xe' for details.", strna(d->name));
                else if (streq(d->result, "invalid"))
                        log_error("%s is not active, cannot reload.", strna(d->name));
                else if (streq(d->result, "assert"))
                        log_error("Assertion failed on job for %s.", strna(d->name));
                else if (streq(d->result, "unsupported"))
                        log_error("Operation on or unit type of %s not supported on this system.", strna(d->name));
                else if (!streq(d->result, "done") && !streq(d->result, "skipped")) {
                        if (d->name) {
                                int q;
                                _cleanup_free_ char *result = NULL;

                                q = bus_job_get_service_result(d, &result);
                                if (q < 0)
                                        log_debug_errno(q, "Failed to get Result property of service %s: %m", d->name);

                                log_job_error_with_service_result(d->name, result, extra_args);
                        } else
                                log_error("Job failed. See \"journalctl -xe\" for details.");
                }
        }

        if (streq(d->result, "canceled"))
                r = -ECANCELED;
        else if (streq(d->result, "timeout"))
                r = -ETIME;
        else if (streq(d->result, "dependency"))
                r = -EIO;
        else if (streq(d->result, "invalid"))
                r = -ENOEXEC;
        else if (streq(d->result, "assert"))
                r = -EPROTO;
        else if (streq(d->result, "unsupported"))
                r = -EOPNOTSUPP;
        else if (!streq(d->result, "done") && !streq(d->result, "skipped"))
                r = -EIO;

        return r;
}

int bus_wait_for_jobs(BusWaitForJobs *d, bool quiet, const char* const* extra_args) {
        int r = 0;

        assert(d);

        while (!set_isempty(d->jobs)) {
                int q;

                q = bus_process_wait(d->bus);
                if (q < 0)
                        return log_error_errno(q, "Failed to wait for response: %m");

                if (d->result) {
                        q = check_wait_response(d, quiet, extra_args);
                        /* Return the first error as it is most likely to be
                         * meaningful. */
                        if (q < 0 && r == 0)
                                r = q;

                        log_debug_errno(q, "Got result %s/%m for job %s", strna(d->result), strna(d->name));
                }

                d->name = mfree(d->name);
                d->result = mfree(d->result);
        }

        return r;
}

int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path) {
        int r;

        assert(d);

        r = set_ensure_allocated(&d->jobs, &string_hash_ops);
        if (r < 0)
                return r;

        return set_put_strdup(d->jobs, path);
}

int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, bool quiet) {
        int r;

        r = bus_wait_for_jobs_add(d, path);
        if (r < 0)
                return log_oom();

        return bus_wait_for_jobs(d, quiet, NULL);
}

int bus_deserialize_and_dump_unit_file_changes(sd_bus_message *m, bool quiet, UnitFileChange **changes, unsigned *n_changes) {
        const char *type, *path, *source;
        int r;

        /* changes is dereferenced when calling unit_file_dump_changes() later,
         * so we have to make sure this is not NULL. */
        assert(changes);
        assert(n_changes);

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sss)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(m, "(sss)", &type, &path, &source)) > 0) {
                /* We expect only "success" changes to be sent over the bus.
                   Hence, reject anything negative. */
                UnitFileChangeType ch = unit_file_change_type_from_string(type);

                if (ch < 0) {
                        log_notice("Manager reported unknown change type \"%s\" for path \"%s\", ignoring.", type, path);
                        continue;
                }

                r = unit_file_changes_add(changes, n_changes, ch, path, source);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error(r);

        unit_file_dump_changes(0, NULL, *changes, *n_changes, false);
        return 0;
}

struct CGroupInfo {
        char *cgroup_path;
        bool is_const; /* If false, cgroup_path should be free()'d */

        Hashmap *pids; /* PID → process name */
        bool done;

        struct CGroupInfo *parent;
        LIST_FIELDS(struct CGroupInfo, siblings);
        LIST_HEAD(struct CGroupInfo, children);
        size_t n_children;
};

static bool IS_ROOT(const char *p) {
        return isempty(p) || streq(p, "/");
}

static int add_cgroup(Hashmap *cgroups, const char *path, bool is_const, struct CGroupInfo **ret) {
        struct CGroupInfo *parent = NULL, *cg;
        int r;

        assert(cgroups);
        assert(ret);

        if (IS_ROOT(path))
                path = "/";

        cg = hashmap_get(cgroups, path);
        if (cg) {
                *ret = cg;
                return 0;
        }

        if (!IS_ROOT(path)) {
                const char *e, *pp;

                e = strrchr(path, '/');
                if (!e)
                        return -EINVAL;

                pp = strndupa(path, e - path);
                if (!pp)
                        return -ENOMEM;

                r = add_cgroup(cgroups, pp, false, &parent);
                if (r < 0)
                        return r;
        }

        cg = new0(struct CGroupInfo, 1);
        if (!cg)
                return -ENOMEM;

        if (is_const)
                cg->cgroup_path = (char*) path;
        else {
                cg->cgroup_path = strdup(path);
                if (!cg->cgroup_path) {
                        free(cg);
                        return -ENOMEM;
                }
        }

        cg->is_const = is_const;
        cg->parent = parent;

        r = hashmap_put(cgroups, cg->cgroup_path, cg);
        if (r < 0) {
                if (!is_const)
                        free(cg->cgroup_path);
                free(cg);
                return r;
        }

        if (parent) {
                LIST_PREPEND(siblings, parent->children, cg);
                parent->n_children++;
        }

        *ret = cg;
        return 1;
}

static int add_process(
                Hashmap *cgroups,
                const char *path,
                pid_t pid,
                const char *name) {

        struct CGroupInfo *cg;
        int r;

        assert(cgroups);
        assert(name);
        assert(pid > 0);

        r = add_cgroup(cgroups, path, true, &cg);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&cg->pids, &trivial_hash_ops);
        if (r < 0)
                return r;

        return hashmap_put(cg->pids, PID_TO_PTR(pid), (void*) name);
}

static void remove_cgroup(Hashmap *cgroups, struct CGroupInfo *cg) {
        assert(cgroups);
        assert(cg);

        while (cg->children)
                remove_cgroup(cgroups, cg->children);

        hashmap_remove(cgroups, cg->cgroup_path);

        if (!cg->is_const)
                free(cg->cgroup_path);

        hashmap_free(cg->pids);

        if (cg->parent)
                LIST_REMOVE(siblings, cg->parent->children, cg);

        free(cg);
}

static int cgroup_info_compare_func(const void *a, const void *b) {
        const struct CGroupInfo *x = *(const struct CGroupInfo* const*) a, *y = *(const struct CGroupInfo* const*) b;

        assert(x);
        assert(y);

        return strcmp(x->cgroup_path, y->cgroup_path);
}

static int dump_processes(
                Hashmap *cgroups,
                const char *cgroup_path,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags) {

        struct CGroupInfo *cg;
        int r;

        assert(prefix);

        if (IS_ROOT(cgroup_path))
                cgroup_path = "/";

        cg = hashmap_get(cgroups, cgroup_path);
        if (!cg)
                return 0;

        if (!hashmap_isempty(cg->pids)) {
                const char *name;
                size_t n = 0, i;
                pid_t *pids;
                void *pidp;
                Iterator j;
                int width;

                /* Order processes by their PID */
                pids = newa(pid_t, hashmap_size(cg->pids));

                HASHMAP_FOREACH_KEY(name, pidp, cg->pids, j)
                        pids[n++] = PTR_TO_PID(pidp);

                assert(n == hashmap_size(cg->pids));
                qsort_safe(pids, n, sizeof(pid_t), pid_compare_func);

                width = DECIMAL_STR_WIDTH(pids[n-1]);

                for (i = 0; i < n; i++) {
                        _cleanup_free_ char *e = NULL;
                        const char *special;
                        bool more;

                        name = hashmap_get(cg->pids, PID_TO_PTR(pids[i]));
                        assert(name);

                        if (n_columns != 0) {
                                unsigned k;

                                k = MAX(LESS_BY(n_columns, 2U + width + 1U), 20U);

                                e = ellipsize(name, k, 100);
                                if (e)
                                        name = e;
                        }

                        more = i+1 < n || cg->children;
                        special = special_glyph(more ? TREE_BRANCH : TREE_RIGHT);

                        fprintf(stdout, "%s%s%*"PID_PRI" %s\n",
                                prefix,
                                special,
                                width, pids[i],
                                name);
                }
        }

        if (cg->children) {
                struct CGroupInfo **children, *child;
                size_t n = 0, i;

                /* Order subcgroups by their name */
                children = newa(struct CGroupInfo*, cg->n_children);
                LIST_FOREACH(siblings, child, cg->children)
                        children[n++] = child;
                assert(n == cg->n_children);
                qsort_safe(children, n, sizeof(struct CGroupInfo*), cgroup_info_compare_func);

                if (n_columns != 0)
                        n_columns = MAX(LESS_BY(n_columns, 2U), 20U);

                for (i = 0; i < n; i++) {
                        _cleanup_free_ char *pp = NULL;
                        const char *name, *special;
                        bool more;

                        child = children[i];

                        name = strrchr(child->cgroup_path, '/');
                        if (!name)
                                return -EINVAL;
                        name++;

                        more = i+1 < n;
                        special = special_glyph(more ? TREE_BRANCH : TREE_RIGHT);

                        fputs(prefix, stdout);
                        fputs(special, stdout);
                        fputs(name, stdout);
                        fputc('\n', stdout);

                        special = special_glyph(more ? TREE_VERTICAL : TREE_SPACE);

                        pp = strappend(prefix, special);
                        if (!pp)
                                return -ENOMEM;

                        r = dump_processes(cgroups, child->cgroup_path, pp, n_columns, flags);
                        if (r < 0)
                                return r;
                }
        }

        cg->done = true;
        return 0;
}

static int dump_extra_processes(
                Hashmap *cgroups,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags) {

        _cleanup_free_ pid_t *pids = NULL;
        _cleanup_hashmap_free_ Hashmap *names = NULL;
        struct CGroupInfo *cg;
        size_t n_allocated = 0, n = 0, k;
        Iterator i;
        int width, r;

        /* Prints the extra processes, i.e. those that are in cgroups we haven't displayed yet. We show them as
         * combined, sorted, linear list. */

        HASHMAP_FOREACH(cg, cgroups, i) {
                const char *name;
                void *pidp;
                Iterator j;

                if (cg->done)
                        continue;

                if (hashmap_isempty(cg->pids))
                        continue;

                r = hashmap_ensure_allocated(&names, &trivial_hash_ops);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(pids, n_allocated, n + hashmap_size(cg->pids)))
                        return -ENOMEM;

                HASHMAP_FOREACH_KEY(name, pidp, cg->pids, j) {
                        pids[n++] = PTR_TO_PID(pidp);

                        r = hashmap_put(names, pidp, (void*) name);
                        if (r < 0)
                                return r;
                }
        }

        if (n == 0)
                return 0;

        qsort_safe(pids, n, sizeof(pid_t), pid_compare_func);
        width = DECIMAL_STR_WIDTH(pids[n-1]);

        for (k = 0; k < n; k++) {
                _cleanup_free_ char *e = NULL;
                const char *name;

                name = hashmap_get(names, PID_TO_PTR(pids[k]));
                assert(name);

                if (n_columns != 0) {
                        unsigned z;

                        z = MAX(LESS_BY(n_columns, 2U + width + 1U), 20U);

                        e = ellipsize(name, z, 100);
                        if (e)
                                name = e;
                }

                fprintf(stdout, "%s%s %*" PID_PRI " %s\n",
                        prefix,
                        special_glyph(TRIANGULAR_BULLET),
                        width, pids[k],
                        name);
        }

        return 0;
}

int unit_show_processes(
                sd_bus *bus,
                const char *unit,
                const char *cgroup_path,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Hashmap *cgroups = NULL;
        struct CGroupInfo *cg;
        int r;

        assert(bus);
        assert(unit);

        if (flags & OUTPUT_FULL_WIDTH)
                n_columns = 0;
        else if (n_columns <= 0)
                n_columns = columns();

        prefix = strempty(prefix);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "GetUnitProcesses",
                        error,
                        &reply,
                        "s",
                        unit);
        if (r < 0)
                return r;

        cgroups = hashmap_new(&string_hash_ops);
        if (!cgroups)
                return -ENOMEM;

        r = sd_bus_message_enter_container(reply, 'a', "(sus)");
        if (r < 0)
                goto finish;

        for (;;) {
                const char *path = NULL, *name = NULL;
                uint32_t pid;

                r = sd_bus_message_read(reply, "(sus)", &path, &pid, &name);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        break;

                r = add_process(cgroups, path, pid, name);
                if (r < 0)
                        goto finish;
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto finish;

        r = dump_processes(cgroups, cgroup_path, prefix, n_columns, flags);
        if (r < 0)
                goto finish;

        r = dump_extra_processes(cgroups, prefix, n_columns, flags);

finish:
        while ((cg = hashmap_first(cgroups)))
               remove_cgroup(cgroups, cg);

        hashmap_free(cgroups);

        return r;
}
