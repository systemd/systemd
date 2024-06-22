/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>

#include "sd-bus.h"

#include "build.h"
#include "bus-error.h"
#include "bus-label.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "errno-list.h"
#include "format-table.h"
#include "json-util.h"
#include "main-func.h"
#include "pager.h"
#include "pretty-print.h"
#include "string-table.h"
#include "strv.h"
#include "sysupdate-update-set-flags.h"
#include "sysupdate-util.h"
#include "terminal-util.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_reboot = false;
static bool arg_offline = false;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;

#define SYSUPDATE_TARGET_INTERFACE "org.freedesktop.sysupdate1.Target"

typedef struct Version {
        char *version;
        UpdateSetFlags flags;
        char **changelog;
        char *contents_json;
} Version;

static void version_clear(Version *v) {
        if (!v)
                return;

        v->version = mfree(v->version);
        v->changelog = strv_free(v->changelog);
        v->flags = 0;
        v->contents_json = mfree(v->contents_json);
}

typedef struct Userdata {
        void *userdata;

        sd_bus *bus;
        sd_event *event;
        unsigned *remaining;

        const char *target_path;
        const char *target_id;

        uint64_t job_id;
        char *job_path;
        sd_event_source *job_interrupt_source;
        sd_bus_slot *job_properties_slot;
        sd_bus_slot *job_finished_slot;
} Userdata;

static Userdata* userdata_free(Userdata *p) {
        if (!p)
                return NULL;

        *p->remaining -= 1;
        if (*p->remaining == 0)
                /* We want to crash the program if we can't exit the loop
                 * cleanly, otherwise it will just hang */
                assert_se(sd_event_exit(p->event, 0) >= 0);

        free(p->job_path);

        sd_event_source_disable_unref(p->job_interrupt_source);
        sd_bus_slot_unref(p->job_properties_slot);
        sd_bus_slot_unref(p->job_finished_slot);

        return mfree(p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Userdata*, userdata_free);

static Userdata* userdata_new(
                void *userdata,
                sd_bus *bus,
                unsigned *remaining,
                const char *target_path,
                const char *target_id) {

        _cleanup_(userdata_freep) Userdata *u = NULL;

        u = new(Userdata, 1);
        if (!u)
                return NULL;

        *u = (Userdata) {
                .userdata = userdata,
                .bus = bus,
                .event = sd_bus_get_event(bus),
                .remaining = remaining,
                .target_path = target_path,
                .target_id = target_id,
        };
        return TAKE_PTR(u);
}

static int ensure_targets(sd_bus *bus, char **argv, char ***ret_targets) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **targets = NULL;
        int r;

        assert(bus);
        assert(ret_targets);

        if (strv_isempty(argv)) {
                const char *class, *name, *path;

                r = bus_call_method(bus, bus_sysupdate_mgr, "ListTargets", &error, &reply, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to call ListTargets: %s", bus_error_message(&error, r));

                r = sd_bus_message_enter_container(reply, 'a', "(sso)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(reply, "(sso)", &class, &name, &path)) > 0) {
                        _cleanup_free_ char *id = NULL;

                        if (streq(class, "host"))
                                id = strdup(".host");
                        else
                                id = strjoin(class, ":", name);
                        if (!id)
                                return log_oom();

                        r = strv_consume(&targets, TAKE_PTR(id));
                        if (r < 0)
                                return r;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return r;

        } else {
                r = strv_extend_strv(&targets, argv, true);
                if (r < 0)
                        return r;
        }

        *ret_targets = TAKE_PTR(targets);
        return 0;
}

static int parse_target(
                const char *in,
                char **ret_bus_path,
                char **ret_version) {
        _cleanup_free_ char *id = NULL, *version = NULL;
        _cleanup_free_ char *escaped = NULL, *objpath = NULL;
        char *s;

        /*
         * Parses the TARGET[@VERSION] syntax from the command line into
         * a bus object locator and an optional version number.
         */

        assert(in);
        assert(ret_bus_path);
        assert(ret_version);

        s = strrchr(in, '@');
        if (s) {
                version = strdup(s + 1);
                if (!version)
                        return -ENOMEM;
                id = strndup(in, s - in);
        } else
                id = strdup(in);
        if (!id)
                return -ENOMEM;

        escaped = bus_label_escape(id);
        if (!escaped)
                return -ENOMEM;

        objpath = strjoin("/org/freedesktop/sysupdate1/target/", escaped);
        if (!objpath)
                return -ENOMEM;

        *ret_bus_path = TAKE_PTR(objpath);
        *ret_version = TAKE_PTR(version);
        return 0;
}

static int parse_targets(
                char **targets,
                size_t *ret_n,
                char ***ret_bus_paths,
                char ***ret_versions) {
        _cleanup_strv_free_ char **bus_paths = NULL;
        _cleanup_strv_free_ char **versions = NULL;
        size_t n = 0;
        int r;

        assert(ret_bus_paths);
        assert(ret_n);

        if (strv_isempty(targets))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No targets found.");

        STRV_FOREACH(id, targets) {
                _cleanup_free_ char *bus_path = NULL, *version = NULL;

                r = parse_target(*id, &bus_path, &version);
                if (r < 0)
                        return log_oom();

                if (version && !ret_versions)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Unexpected version specifier in target: %s",
                                               *id);

                r = strv_extend(&bus_paths, strempty(bus_path));
                if (r < 0)
                        return r;

                r = strv_extend(&versions, strempty(version));
                if (r < 0)
                        return r;

                n++;
        }

        *ret_n = n;
        *ret_bus_paths = TAKE_PTR(bus_paths);
        if (ret_versions)
                *ret_versions = TAKE_PTR(versions);
        return 0;
}

static int log_bus_error(int r, const sd_bus_error *error, const char *target, const char *action) {
        assert(action);

        if (r == 0) {
                assert(sd_bus_error_is_set(error));
                r = sd_bus_error_get_errno(error);
        }

        if (sd_bus_error_has_name(error, SD_BUS_ERROR_UNKNOWN_OBJECT)) {
                if (target)
                        return log_error_errno(r, "Invalid target: %s", target);
                else
                        return log_error_errno(r, "Invalid target");
        }

        if (target)
                return log_error_errno(r, "Failed to %s for '%s': %s", action, target,
                                       bus_error_message(error, r));
        else
                return log_error_errno(r, "Failed to %s: %s", action, bus_error_message(error, r));
}

static int list_targets(sd_bus *bus) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **targets = NULL, **target_paths = NULL;
        size_t n;
        int r;

        assert(bus);

        r = ensure_targets(bus, /* argv= */ NULL, &targets);
        if (r < 0)
                return r;

        r = parse_targets(targets, &n, &target_paths, /* ret_versions= */ NULL);
        if (r < 0)
                return r;

        table = table_new("target", "version", "path");
        if (!table)
                return log_oom();

        for (size_t i = 0; i < n; i++) {
                char *version = NULL, *path = NULL;

                r = sd_bus_call_method(bus, bus_sysupdate_mgr->destination, target_paths[i], SYSUPDATE_TARGET_INTERFACE, "GetVersion", &error, &reply, "");
                if (r < 0)
                        return log_bus_error(r, &error, targets[i], "get Version");
                r = sd_bus_message_read_basic(reply, 's', &version);
                if (r < 0)
                        return log_bus_error(r, &error, targets[i], "get Version");

                r = sd_bus_get_property_string(bus, bus_sysupdate_mgr->destination, target_paths[i], SYSUPDATE_TARGET_INTERFACE, "Path", &error, &path);
                if (r < 0)
                        return log_bus_error(r, &error, targets[i], "get Path");

                r = table_add_many(table,
                                   TABLE_STRING, targets[i],
                                   TABLE_STRING, empty_to_dash(version),
                                   TABLE_STRING, path);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return table_print_with_pager(table, SD_JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
}

static int parse_describe(sd_bus_message *reply, Version *ret) {
        _cleanup_(version_clear) Version v = {};
        char *version_json = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
        int r;

        assert(reply);
        assert(ret);

        r = sd_bus_message_read_basic(reply, 's', &version_json);

        r = sd_json_parse(version_json, 0, &json, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON: %m");

        assert(sd_json_variant_is_object(json));

        const char *key;
        sd_json_variant *value;
        JSON_VARIANT_OBJECT_FOREACH(key, value, json) {
                if (streq(key, "version")) {
                        assert(sd_json_variant_is_string(value));
                        assert_se(v.version = strdup(sd_json_variant_string(value)));
                } else if (streq(key, "newest")) {
                        assert(sd_json_variant_is_boolean(value));
                        if (sd_json_variant_boolean(value))
                                v.flags |= UPDATE_NEWEST;
                } else if (streq(key, "available")) {
                        assert(sd_json_variant_is_boolean(value));
                        if (sd_json_variant_boolean(value))
                                v.flags |= UPDATE_AVAILABLE;
                } else if (streq(key, "installed")) {
                        assert(sd_json_variant_is_boolean(value));
                        if (sd_json_variant_boolean(value))
                                v.flags |= UPDATE_INSTALLED;
                } else if (streq(key, "obsolete")) {
                        assert(sd_json_variant_is_boolean(value));
                        if (sd_json_variant_boolean(value))
                                v.flags |= UPDATE_OBSOLETE;
                } else if (streq(key, "protected")) {
                        assert(sd_json_variant_is_boolean(value));
                        if (sd_json_variant_boolean(value))
                                v.flags |= UPDATE_PROTECTED;
                } else if (streq(key, "changelog-url")) {
                        sd_json_variant *entry;
                        assert(sd_json_variant_is_array(value));
                        JSON_VARIANT_ARRAY_FOREACH(entry, value) {
                                assert(sd_json_variant_is_string(entry));
                                r = strv_extend(&v.changelog, sd_json_variant_string(entry));
                                if (r < 0)
                                        log_error_errno(r, "Failed to parse JSON: %m");
                        }
                } else if (streq(key, "contents")) {
                        r = sd_json_variant_format(value, 0, &v.contents_json);
                        if (r < 0)
                                log_error_errno(r, "Failed to parse JSON: %m");
                } else
                        assert_not_reached();
        }

        *ret = TAKE_STRUCT(v);
        return 0;
}

static int list_versions_finished(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        Table *table = ASSERT_PTR(data->userdata);
        const sd_bus_error *e;
        _cleanup_(version_clear) Version v = {};
        _cleanup_free_ char *version_link = NULL;
        const char *color;
        int r;

        assert(reply);

        e = sd_bus_message_get_error(reply);
        if (e)
                return log_bus_error(0, e, NULL, "call Describe");

        r = parse_describe(reply, &v);
        if (r < 0)
                return r;

        color = update_set_flags_to_color(v.flags);

        if (urlify_enabled() && v.changelog) {
                version_link = strjoin(v.version, special_glyph(SPECIAL_GLYPH_EXTERNAL_LINK));
                if (!version_link)
                        return log_oom();
        }

        r = table_add_many(table,
                           TABLE_STRING,    update_set_flags_to_glyph(v.flags),
                           TABLE_SET_COLOR, color,
                           TABLE_STRING,    version_link ?: v.version,
                           TABLE_SET_COLOR, color,
                           TABLE_SET_URL,   v.changelog,
                           TABLE_STRING,    update_set_flags_to_string(v.flags),
                           TABLE_SET_COLOR, color);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int list_versions(sd_bus *bus, const char *target_path) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **versions = NULL;
        unsigned remaining = 0;
        int r;

        r = sd_bus_call_method(bus, bus_sysupdate_mgr->destination, target_path, SYSUPDATE_TARGET_INTERFACE, "List", &error, &reply, "b", arg_offline);
        if (r < 0)
                return log_bus_error(r, &error, NULL, "call List");

        r = sd_bus_message_read_strv(reply, &versions);
        if (r < 0)
                return bus_log_parse_error(r);

        table = table_new("", "version", "status");
        if (!table)
                return log_oom();

        (void) table_set_sort(table, 1);
        (void) table_set_reverse(table, 1, true);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set up interrupt handler: %m");

        STRV_FOREACH(version, versions) {
                _cleanup_(userdata_freep) Userdata *u = NULL;
                u = userdata_new(table, bus, &remaining, NULL, NULL);
                if (!u)
                        return log_oom();

                r = sd_bus_call_method_async(bus, NULL, bus_sysupdate_mgr->destination, target_path, SYSUPDATE_TARGET_INTERFACE, "Describe", list_versions_finished, u, "sb", *version, arg_offline);
                if (r < 0)
                        return r;
                TAKE_PTR(u);

                remaining++;
        }

        r = sd_event_loop(event);
        if (r < 0)
                return r;

        return table_print_with_pager(table, SD_JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
}

static int describe(sd_bus *bus, const char *target_path, const char *version) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
        _cleanup_(version_clear) Version v = {};
        _cleanup_free_ char *changelog_link = NULL;
        _cleanup_strv_free_ char **changelog_links = NULL;
        sd_json_variant *entry;
        const char *color;
        int r;

        r = sd_bus_call_method(bus, bus_sysupdate_mgr->destination, target_path, SYSUPDATE_TARGET_INTERFACE, "Describe", &error, &reply, "sb", version, arg_offline);
        if (r < 0)
                return log_bus_error(r, &error, NULL, "call Describe");

        r = parse_describe(reply, &v);
        if (r < 0)
                return r;

        color = strempty(update_set_flags_to_color(v.flags));

        printf("%s%s%s Version: %s\n"
               "    State: %s%s%s\n",
               color, update_set_flags_to_glyph(v.flags), ansi_normal(), v.version,
               color, update_set_flags_to_string(v.flags), ansi_normal());
        if (v.changelog)
                STRV_FOREACH(url, v.changelog) {
                        r = terminal_urlify(*url, NULL, &changelog_link);
                        if (r < 0)
                                return r;
                        r = strv_extend(&changelog_links, changelog_link);
                        if (r < 0)
                                return r;
                        printf("ChangeLog: %s\n", strna(changelog_link));
                }
        printf("\n");

        r = sd_json_parse(v.contents_json, 0, &json, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON: %m");

        assert(sd_json_variant_is_array(json));

        JSON_VARIANT_ARRAY_FOREACH(entry, json) {
                assert(sd_json_variant_is_object(entry));
                const char *key;
                sd_json_variant *value;

                if (!table) {
                         table = table_new_raw(sd_json_variant_elements(entry) / 2);
                         if (!table)
                                return log_oom();

                        JSON_VARIANT_OBJECT_FOREACH(key, value, entry) {

                                r = table_add_cell(table, NULL, TABLE_HEADER, key);
                                if (r < 0)
                                        return table_log_add_error(r);
                        }
                }

                JSON_VARIANT_OBJECT_FOREACH(key, value, entry) {
                        TableDataType type;
                        uint64_t number;
                        bool boolean;
                        const void *data;

                        if (sd_json_variant_is_string(value)) {
                                type = TABLE_STRING;
                                assert_se(data = sd_json_variant_string(value));
                        } else if (sd_json_variant_is_unsigned(value)) {
                                type = TABLE_UINT64;
                                number = sd_json_variant_unsigned(value);
                                data = &number;
                        } else if (sd_json_variant_is_boolean(value)) {
                                type = TABLE_BOOLEAN;
                                boolean = sd_json_variant_boolean(value);
                                data = &boolean;
                        } else if (sd_json_variant_is_null(value)) {
                                type = TABLE_EMPTY;
                                data = NULL;
                        } else
                                assert_not_reached();

                        if (streq(key, "ptflags"))
                                type = TABLE_UINT64_HEX;
                        else if (streq(key, "size"))
                                type = TABLE_SIZE;
                        else if (streq(key, "mode"))
                                type = TABLE_MODE;
                        else if (streq(key, "mtime"))
                                type = TABLE_TIMESTAMP;

                        r = table_add_cell(table, NULL, type, data);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        return table_print_with_pager(table, SD_JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
}

static int verb_list(int argc, char **argv, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        if (argc == 1)
                return list_targets(bus);
        else {
                _cleanup_free_ char *target_path = NULL;
                _cleanup_free_ char *version = NULL;

                r = parse_target(argv[1], &target_path, &version);
                if (r < 0)
                        return log_oom();

                if (!version)
                        return list_versions(bus, target_path);
                else
                        return describe(bus, target_path, version);
        }

        return 0;
}

static int check_describe_finished(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        Table *table = ASSERT_PTR(data->userdata);
        _cleanup_(version_clear) Version v = {};
        _cleanup_free_ char *update = NULL;
        const sd_bus_error *e;

        const char *lnk = NULL;
        int r;

        assert(reply);

        e = sd_bus_message_get_error(reply);
        if (e)
                return log_bus_error(0, e, NULL, "call Describe");

        r = parse_describe(reply, &v);
        if (r < 0)
                return r;

        if (urlify_enabled() && v.changelog)
                lnk = special_glyph(SPECIAL_GLYPH_EXTERNAL_LINK);
        update = strjoin(empty_to_dash(v.version), " ",
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), " ",
                         v.version, strempty(lnk));
        if (!update)
                return log_oom();

        r = table_add_many(table,
                           TABLE_STRING, data->target_id,
                           TABLE_STRING, update,
                           TABLE_SET_URL, v.changelog);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int check_finished(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        const char *new_version = NULL;
        int r;

        assert(reply);

        e = sd_bus_message_get_error(reply);
        if (e)
                return log_bus_error(0, e, data->target_id, "call CheckNew");

        r = sd_bus_message_read(reply, "s", &new_version);
        if (r < 0)
                return bus_log_parse_error(r);

        if (isempty(new_version))
                return 0;

        r = sd_bus_call_method_async(data->bus, NULL, bus_sysupdate_mgr->destination, data->target_path, SYSUPDATE_TARGET_INTERFACE, "Describe",
                                  check_describe_finished, data,
                                  "sb", new_version, arg_offline);
        if (r < 0)
                return r;
        TAKE_PTR(data);

        return 0;
}

static int verb_check(int argc, char **argv, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_strv_free_ char **targets = NULL;
        _cleanup_strv_free_ char **target_paths = NULL;
        size_t n;
        unsigned remaining = 0;
        int r;

        r = ensure_targets(bus, argv + 1, &targets);
        if (r < 0)
                return r;

        r = parse_targets(targets, &n, &target_paths, /* ret_versions= */ NULL);
        if (r < 0)
                return r;

        table = table_new("target", "update");
        if (!table)
                return log_oom();

        (void) table_set_sort(table, 0);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set up interrupt handler: %m");

        for (size_t i = 0; i < n; i++) {
                _cleanup_(userdata_freep) Userdata *u = NULL;
                u = userdata_new(table, bus, &remaining, target_paths[i], targets[i]);
                if (!u)
                        return log_oom();

                r = sd_bus_call_method_async(bus, NULL, bus_sysupdate_mgr->destination, target_paths[i], SYSUPDATE_TARGET_INTERFACE, "CheckNew", check_finished, u, NULL);
                if (r < 0)
                        return r;
                TAKE_PTR(u);

                remaining++;
        }

        r = sd_event_loop(event);
        if (r < 0)
                return r;

        return table_print_with_pager(table, SD_JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
}

#define UPDATE_PROGRESS_FAILED INT_MIN
/* Make sure it doesn't overlap w/ errno values */
assert_cc(UPDATE_PROGRESS_FAILED < -ERRNO_MAX);

static int update_render_progress(sd_event_source *source, void *userdata) {
        OrderedHashmap *map = ASSERT_PTR(userdata);
        const char *target;
        void *p;
        unsigned total;
        size_t n;
        bool exiting;

        exiting = sd_event_get_state(sd_event_source_get_event(source)) == SD_EVENT_EXITING;

        total = 0;
        n = ordered_hashmap_size(map);

        if (n == 0)
                return 0;

        if (!terminal_is_dumb()) {
                for (size_t i = 0; i <= n; i++) {
                        fputs("\n", stderr); /* Possibly scroll the terminal to make room (including total)*/
                }
                fprintf(stderr, "\x1B[%zuF", n+1); /* Go back */

                fputs("\x1B""7", stderr); /* Save cursor position */
                fputs("\x1B[?25l", stderr); /* Hide cursor */
        }

        ORDERED_HASHMAP_FOREACH_KEY(p, target, map) {
                int progress = PTR_TO_INT(p);

                if (progress == UPDATE_PROGRESS_FAILED) {
                        fprintf(stderr, "%s %s\n", RED_CROSS_MARK(), target);
                        total += 100;
                } else if (progress == -EALREADY) {
                        fprintf(stderr, "%s %s (Already up-to-date)\n", GREEN_CHECK_MARK(), target);
                        n--; /* Don't consider this target in the total */
                } else if (progress < 0) {
                        fprintf(stderr, "%s %s (%s)\n", RED_CROSS_MARK(), target, STRERROR(progress));
                        total += 100;
                } else {
                        draw_progress_bar(target, progress);
                        fputs("\n", stderr);
                        total += progress;
                }
        }

        if (n > 1) {
                draw_progress_bar("TOTAL", total / n);
                fputs("\n", stderr);
        }

        if (!terminal_is_dumb()) {
                if (exiting)
                        fputs("\x1B[?25h", stderr); /* Show cursor again */
                else
                        fputs("\x1B""8", stderr); /* Restore cursor position */
        } else if (!exiting)
                fputs("------\n", stderr);

        fflush(stderr);
        return 0;
}

static int update_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Userdata *data = ASSERT_PTR(userdata);
        OrderedHashmap *map = ASSERT_PTR(data->userdata);
        const char *interface;
        unsigned progress = UINT_MAX;
        const struct bus_properties_map prop_map[] = {
                { "Progress", "u", NULL, PTR_TO_SIZE(&progress) },
                {}
        };
        int r;

        assert(m);

        r = sd_bus_message_read(m, "s", &interface);
        if (r < 0) {
                bus_log_parse_error_debug(r);
                return 0;
        }

        if (!streq(interface, "org.freedesktop.sysupdate1.Job"))
                return 0;

        r = bus_message_map_all_properties(m, prop_map, /* flags= */ 0, error, NULL);
        if (r < 0)
                return 0; /* map_all_properties does the debug logging internally... */

        if (progress == UINT_MAX)
                return 0;

        r = ordered_hashmap_replace(map, data->target_id, INT_TO_PTR((int) progress));
        if (r < 0)
                log_debug_errno(r, "Failed to update hashmap: %m");
        return 0;
}

static int update_finished(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        OrderedHashmap *map = ASSERT_PTR(data->userdata);
        uint32_t id;
        int r, status;

        assert(m);

        r = sd_bus_message_read(m, "uoi", &id, NULL, &status);
        if (r < 0) {
                bus_log_parse_error_debug(r);
                return 0;
        }

        if (id != data->job_id) {
                TAKE_PTR(data);
                return 0;
        }

        if (status == 0) /* success */
                status = 100;
        else if (status > 0) /* exit status without errno */
                status = UPDATE_PROGRESS_FAILED; /* i.e. EXIT_FAILURE */
        /* else errno */

        r = ordered_hashmap_replace(map, data->target_id, INT_TO_PTR(status));
        if (r < 0)
                log_debug_errno(r, "Failed to update hashmap: %m");
        return 0;
}

static int update_interrupted(sd_event_source *source, void *userdata) {
        /* Since the event loop is exiting, we will never recieve the JobRemoved
         * signal. So, we must free the userdata here. */
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        OrderedHashmap *map = ASSERT_PTR(data->userdata);
        int r;

        r = sd_bus_call_method(data->bus,
                               bus_sysupdate_mgr->destination,
                               data->job_path,
                               "org.freedesktop.sysupdate1.Job",
                               "Cancel",
                               &error, /* reply= */ NULL,
                               NULL);
        if (r < 0)
                return log_bus_error(r, &error, NULL, "call Cancel");

        r = ordered_hashmap_replace(map, data->target_id, INT_TO_PTR(-ECANCELED));
        if (r < 0)
                log_debug_errno(r, "Failed to update hashmap: %m");

        return 0;
}

static int update_started(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        OrderedHashmap *map = ASSERT_PTR(data->userdata);
        const sd_bus_error *e;
        _cleanup_free_ char *key = NULL;
        const char *new_version, *job_path;
        int r;

        assert(reply);

        e = sd_bus_message_get_error(reply);
        if (e) {
                r = -sd_bus_error_get_errno(e);

                key = strdup(data->target_id);
                if (!key)
                        return log_oom();
                r = ordered_hashmap_put(map, key, INT_TO_PTR(r));
                if (r < 0)
                        return log_debug_errno(r, "Failed to update hashmap: %m");
                TAKE_PTR(key);

                return r;
        }

        r = sd_bus_message_read(reply, "suo", &new_version, &data->job_id, &job_path);
        if (r < 0)
                return bus_log_parse_error(r);
        data->job_path = strdup(job_path);
        if (!data->job_path)
                return log_oom();
        if (isempty(new_version)) {
                new_version = "latest";
        }

        /* Register this job into the hashmap. This will give it a progress bar */
        if (strchr(data->target_id, '@'))
                key = strdup(data->target_id);
        else
                key = strjoin(data->target_id, "@", new_version);
        if (!key)
                return log_oom();
        r = ordered_hashmap_put(map, key, INT_TO_PTR(0)); /* takes ownership of key */
        if (r < 0)
                return r;
        data->target_id = TAKE_PTR(key); /* just borrowing */

        /* Cancel the job if the event loop exits */
        r = sd_event_add_exit(data->event, &data->job_interrupt_source, update_interrupted, data);
        if (r < 0)
                return log_error_errno(r, "Failed to set up interrupt handler: %m");

        /* We need to cancel the job before the final iteration of the renderer runs */
        r = sd_event_source_set_priority(data->job_interrupt_source, SD_EVENT_PRIORITY_IMPORTANT);
        if (r < 0)
                return log_error_errno(r, "Failed to set interrupt priority: %m");

        /* Register for progress notifications */
        r = sd_bus_match_signal_async(data->bus,
                                      &data->job_properties_slot,
                                      bus_sysupdate_mgr->destination,
                                      job_path,
                                      "org.freedesktop.DBus.Properties",
                                      "PropertiesChanged",
                                      update_properties_changed,
                                      NULL,
                                      data);
        if (r < 0)
                return log_bus_error(r, NULL, data->target_id, "listen for PropertiesChanged");

        /* Register for notification when the job ends */
        r = bus_match_signal_async(data->bus,
                                   &data->job_finished_slot,
                                   bus_sysupdate_mgr,
                                   "JobRemoved",
                                   update_finished,
                                   NULL,
                                   data);
        if (r < 0)
                return log_bus_error(r, NULL, data->target_id, "listen for JobRemoved");
        TAKE_PTR(data); /* update_finished/update_interrupted take ownership of the data */

        return 0;
}

static int verb_update(int argc, char **argv, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *render_exit = NULL;
        _cleanup_ordered_hashmap_free_ OrderedHashmap *map = NULL;
        _cleanup_strv_free_ char **targets = NULL, **versions = NULL, **target_paths = NULL;
        size_t n;
        unsigned remaining = 0;
        void *p;
        bool did_anything = false;
        int r;

        r = ensure_targets(bus, argv + 1, &targets);
        if (r < 0)
                return r;

        r = parse_targets(targets, &n, &target_paths, &versions);
        if (r < 0)
                return r;

        map = ordered_hashmap_new(&string_hash_ops_free);
        if (!map)
                return log_oom();

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set up interrupt handler: %m");

        for (size_t i = 0; i < n; i++) {
                _cleanup_(userdata_freep) Userdata *u = NULL;
                u = userdata_new(map, bus, &remaining, target_paths[i], targets[i]);
                if (!u)
                        return log_oom();

                r = sd_bus_call_method_async(bus, NULL, bus_sysupdate_mgr->destination, target_paths[i], SYSUPDATE_TARGET_INTERFACE, "Update", update_started, u,
                                          "s", versions[i]);
                if (r < 0)
                        return r;
                TAKE_PTR(u);

                remaining++;
        }

        /* Set up the rendering */
        r = sd_event_add_post(event, NULL, update_render_progress, map);
        if (r < 0)
                return r;

        r = sd_event_add_exit(event, &render_exit, update_render_progress, map);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(render_exit, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return r;

        r = sd_event_loop(event);
        if (r < 0)
                return r;

        ORDERED_HASHMAP_FOREACH(p, map) {
                r = PTR_TO_INT(p);
                if (r == -EALREADY)
                        continue;
                if (r == UPDATE_PROGRESS_FAILED)
                        return EXIT_FAILURE;
                if (r < 0)
                        return r;

                did_anything = true;
        }

        if (arg_reboot) {
                if (did_anything)
                        return reboot_now();
                log_info("Nothing was updated... skipping reboot.");
        }

        return 0;
}

static int verb_vacuum(int argc, char **argv, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **targets = NULL, **target_paths = NULL;
        size_t n;
        int r;

        r = ensure_targets(bus, argv + 1, &targets);
        if (r < 0)
                return r;

        r = parse_targets(targets, &n, &target_paths, /* ret_versions= */ NULL);
        if (r < 0)
                return r;

        for (size_t i = 0; i < n; i++) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                uint32_t count, disabled;

                r = sd_bus_call_method(bus, bus_sysupdate_mgr->destination, target_paths[i], SYSUPDATE_TARGET_INTERFACE, "Vacuum", &error, &reply, NULL);
                if (r < 0)
                        return log_bus_error(r, &error, targets[i], "call Vacuum");

                r = sd_bus_message_read(reply, "uu", &count, &disabled);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (count > 0 && disabled > 0)
                        log_info("Deleted %u instance(s) and %u disabled transfer(s) of %s.",
                                 count, disabled, targets[i]);
                else if (count > 0)
                        log_info("Deleted %u instance(s) of %s.", count, targets[i]);
                else if (disabled > 0)
                        log_info("Deleted %u disabled transfer(s) of %s.", disabled, targets[i]);
                else
                        log_info("Found nothing to delete for %s.", targets[i]);
        }
        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("updatectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [VERSION]\n"
               "\n%5$sManage system updates.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  list [TARGET[@VERSION]]       List available targets and versions\n"
               "  check [TARGET...]             Check for updates\n"
               "  update [TARGET[@VERSION]...]  Install updates\n"
               "  vacuum [TARGET...]            Clean up old updates\n"
               "  -h --help                     Show this help\n"
               "     --version                  Show package version\n"
               "\n%3$sOptions:%4$s\n"
               "     --reboot             Reboot after updating to newer version\n"
               "     --offline            Do not fetch metadata from the network\n"
               "  -H --host=[USER@]HOST   Operate on remote host\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "\nSee the %2$s for details.\n"
               , program_invocation_short_name
               , link
               , ansi_underline(), ansi_normal()
               , ansi_highlight(), ansi_normal()
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_REBOOT,
                ARG_OFFLINE,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'             },
                { "version",   no_argument,       NULL, ARG_VERSION     },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER    },
                { "no-legend", no_argument,       NULL, ARG_NO_LEGEND   },
                { "host",      required_argument, NULL, 'H'             },
                { "reboot",    no_argument,       NULL, ARG_REBOOT      },
                { "offline",   no_argument,       NULL, ARG_OFFLINE     },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:", options, NULL)) >= 0) {
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case ARG_REBOOT:
                        arg_reboot = true;
                        break;

                case ARG_OFFLINE:
                        arg_offline = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        static const Verb verbs[] = {
                { "list",   VERB_ANY, 2,        VERB_DEFAULT|VERB_ONLINE_ONLY, verb_list     },
                { "check",  VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,              verb_check    },
                { "update", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,              verb_update   },
                { "vacuum", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,              verb_vacuum   },
                {}
        };

        setlocale(LC_ALL, "");
        log_setup();

        (void) signal(SIGWINCH, columns_lines_cache_reset);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, RUNTIME_SCOPE_SYSTEM, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        if (arg_transport == BUS_TRANSPORT_LOCAL)
                polkit_agent_open();

        return dispatch_verb(argc, argv, verbs, bus);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
