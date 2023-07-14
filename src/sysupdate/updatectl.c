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
#include "json.h"
#include "main-func.h"
#include "pager.h"
#include "pretty-print.h"
#include "string-table.h"
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

typedef struct Version {
        char *version;
        UpdateSetFlags flags;
        char *changelog;
        char *contents_json;
} Version;

static void version_clear(Version *v) {
        if (!v)
                return;

        v->version = mfree(v->version);
        v->changelog = mfree(v->changelog);
        v->flags = 0;
        v->contents_json = mfree(v->contents_json);
}

typedef struct Userdata {
        void *userdata;

        sd_bus *bus;
        sd_event *event;
        unsigned *remaining;

        BusLocator *target;
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
                BusLocator *target,
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
                .target = target,
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
                                id = strdup("host");
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
                BusLocator **ret_object,
                char **ret_version) {
        _cleanup_free_ char *id = NULL, *version = NULL;
        _cleanup_free_ char *escaped = NULL, *objpath = NULL;
        _cleanup_(bus_locator_freep) BusLocator *object = NULL;
        char *s;

        /*
         * Parses the TARGET[@VERSION] syntax from the command line into
         * a bus object locator and an optional version number.
         */

        assert(in);
        assert(ret_object);
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

        object = bus_locator_new(bus_sysupdate_mgr->destination,
                                 "org.freedesktop.sysupdate1.Target",
                                 objpath);
        if (!object)
                return -ENOMEM;

        *ret_object = TAKE_PTR(object);
        *ret_version = TAKE_PTR(version);
        return 0;
}

static void parse_targets_free(BusLocator **objects, size_t n) {
        for (size_t i = 0; i < n; i++)
                bus_locator_free(objects[i]);
        free(objects);
}

static int parse_targets(
                char **targets,
                size_t *ret_n,
                BusLocator ***ret_objects,
                char ***ret_versions) {
        BusLocator **objects = NULL;
        _cleanup_strv_free_ char **versions = NULL;
        size_t n = 0;
        int r;

        assert(targets);
        assert(ret_objects);
        assert(ret_n);

        CLEANUP_ARRAY(objects, n, parse_targets_free);

        if (strv_isempty(targets))
                return log_error_errno(SYNTHETIC_ERRNO(-ENOENT), "No targets found.");

        STRV_FOREACH(id, targets) {
                _cleanup_(bus_locator_freep) BusLocator *object = NULL;
                _cleanup_free_ char *version = NULL;

                r = parse_target(*id, &object, &version);
                if (r < 0)
                        return log_oom();

                if (version && !ret_versions)
                        return log_error_errno(SYNTHETIC_ERRNO(-EINVAL),
                                               "Unexpected version specifier in target: %s",
                                               *id);

                if (!GREEDY_REALLOC(objects, n + 1))
                        return log_oom();
                objects[n++] = TAKE_PTR(object);

                r = strv_extend(&versions, strempty(version));
                if (r < 0)
                        return r;
        }

        *ret_n = n;
        *ret_objects = TAKE_PTR(objects);
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
        _cleanup_strv_free_ char **targets = NULL;
        BusLocator **objects = NULL;
        size_t n;
        int r;

        assert(bus);

        CLEANUP_ARRAY(objects, n, parse_targets_free);

        r = ensure_targets(bus, /* argv= */ NULL, &targets);
        if (r < 0)
                return r;

        r = parse_targets(targets, &n, &objects, /* ret_versions= */ NULL);
        if (r < 0)
                return r;

        table = table_new("target", "version", "path");
        if (!table)
                return log_oom();

        for (size_t i = 0; i < n; i++) {
                _cleanup_free_ char *version = NULL, *path = NULL;

                r = bus_get_property_string(bus, objects[i], "Version", &error, &version);
                if (r < 0)
                        return log_bus_error(r, &error, targets[i], "get Version");

                r = bus_get_property_string(bus, objects[i], "Path", &error, &path);
                if (r < 0)
                        return log_bus_error(r, &error, targets[i], "get Path");

                r = table_add_many(table,
                                   TABLE_STRING, targets[i],
                                   TABLE_STRING, empty_to_dash(version),
                                   TABLE_STRING, path);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return table_print_with_pager(table, JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
}

static int map_version_flags(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {
        UpdateSetFlags *ret = ASSERT_PTR(userdata);
        static const char *const table[] = {
                [UPDATE_NEWEST]    = "newest",
                [UPDATE_AVAILABLE] = "available",
                [UPDATE_INSTALLED] = "installed",
                [UPDATE_OBSOLETE]  = "obsolete",
                [UPDATE_PROTECTED] = "protected",
        };
        ssize_t flag;
        int r, b;

        assert(m);

        r = sd_bus_message_read_basic(m, 'b', &b);
        if (r < 0)
                return bus_log_parse_error_debug(r);

        if (b) {
                assert_se((flag = string_table_lookup(table, ELEMENTSOF(table), member)) >= 0);
                *ret |= (UpdateSetFlags) flag;
        }

        return 0;
}

static int parse_describe(sd_bus_message *reply, Version *ret) {
        static const struct bus_properties_map map[] = {
                { "version",       "s", NULL,              offsetof(Version, version)       },
                { "newest",        "b", map_version_flags, offsetof(Version, flags)         },
                { "available",     "b", map_version_flags, offsetof(Version, flags)         },
                { "installed",     "b", map_version_flags, offsetof(Version, flags)         },
                { "obsolete",      "b", map_version_flags, offsetof(Version, flags)         },
                { "protected",     "b", map_version_flags, offsetof(Version, flags)         },
                { "changelog-url", "s", NULL,              offsetof(Version, changelog)     },
                { "_contents",     "s", NULL,              offsetof(Version, contents_json) },
                {}
        };
        _cleanup_(version_clear) Version v = {};
        int r;

        assert(reply);
        assert(ret);

        r = bus_message_map_all_properties(reply, map, BUS_MAP_STRDUP, NULL, &v);
        if (r < 0)
                return bus_log_parse_error(r);

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

static int list_versions(sd_bus *bus, BusLocator *target) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **versions = NULL;
        unsigned remaining = 0;
        int r;

        r = bus_call_method(bus, target, "List", &error, &reply, "b", arg_offline);
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

                r = bus_call_method_async(bus, NULL, target, "Describe", list_versions_finished, u,
                                          "sb", *version, arg_offline);
                if (r < 0)
                        return r;
                TAKE_PTR(u);

                remaining++;
        }

        r = sd_event_loop(event);
        if (r < 0)
                return r;

        return table_print_with_pager(table, JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
}

static int describe(sd_bus *bus, BusLocator *target, const char *version) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *json = NULL;
        _cleanup_(version_clear) Version v = {};
        _cleanup_free_ char *changelog_link = NULL;
        JsonVariant *entry;
        const char *color;
        int r;

        r = bus_call_method(bus, target, "Describe", &error, &reply, "sb", version, arg_offline);
        if (r < 0)
                return log_bus_error(r, &error, NULL, "call Describe");

        r = parse_describe(reply, &v);
        if (r < 0)
                return r;

        color = strempty(update_set_flags_to_color(v.flags));

        if (v.changelog) {
                r = terminal_urlify(v.changelog, NULL, &changelog_link);
                if (r < 0)
                        return r;
        }

        printf("%s%s%s Version: %s\n"
               "    State: %s%s%s\n"
               "Changelog: %s\n"
               "\n",
               color, update_set_flags_to_glyph(v.flags), ansi_normal(), v.version,
               color, update_set_flags_to_string(v.flags), ansi_normal(),
               strna(changelog_link));

        r = json_parse(v.contents_json, 0, &json, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON: %m");

        assert(json_variant_is_array(json));

        JSON_VARIANT_ARRAY_FOREACH(entry, json) {
                assert(json_variant_is_object(entry));
                const char *key;
                JsonVariant *value;

                if (!table) {
                         table = table_new_raw(json_variant_elements(entry) / 2);
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

                        if (json_variant_is_string(value)) {
                                type = TABLE_STRING;
                                assert_se(data = json_variant_string(value));
                        } else if (json_variant_is_unsigned(value)) {
                                type = TABLE_UINT64;
                                number = json_variant_unsigned(value);
                                data = &number;
                        } else if (json_variant_is_boolean(value)) {
                                type = TABLE_BOOLEAN;
                                boolean = json_variant_boolean(value);
                                data = &boolean;
                        } else if (json_variant_is_null(value)) {
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

        return table_print_with_pager(table, JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
}

static int verb_list(int argc, char **argv, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        if (argc == 1)
                return list_targets(bus);
        else {
                _cleanup_(bus_locator_freep) BusLocator *object = NULL;
                _cleanup_free_ char *version = NULL;

                r = parse_target(argv[1], &object, &version);
                if (r < 0)
                        return log_oom();

                if (!version)
                        return list_versions(bus, object);
                else
                        return describe(bus, object, version);
        }

        return 0;
}

static int check_describe_finished(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        Table *table = ASSERT_PTR(data->userdata);
        _cleanup_(version_clear) Version v = {};
        _cleanup_free_ char *version = NULL, *update = NULL;
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

        r = bus_get_property_string(data->bus, data->target, "Version", ret_error, &version);
        if (r < 0)
                return log_bus_error(r, ret_error, data->target_id, "get Version");

        if (urlify_enabled() && v.changelog)
                lnk = special_glyph(SPECIAL_GLYPH_EXTERNAL_LINK);
        update = strjoin(empty_to_dash(version), " ",
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

        r = bus_call_method_async(data->bus, NULL, data->target, "Describe",
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
        BusLocator **objects = NULL;
        size_t n;
        unsigned remaining = 0;
        int r;

        CLEANUP_ARRAY(objects, n, parse_targets_free);

        r = ensure_targets(bus, argv + 1, &targets);
        if (r < 0)
                return r;

        r = parse_targets(targets, &n, &objects, /* ret_versions= */ NULL);
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
                u = userdata_new(table, bus, &remaining, objects[i], targets[i]);
                if (!u)
                        return log_oom();

                r = bus_call_method_async(bus, NULL, objects[i], "CheckNew", check_finished, u, NULL);
                if (r < 0)
                        return r;
                TAKE_PTR(u);

                remaining++;
        }

        r = sd_event_loop(event);
        if (r < 0)
                return r;

        return table_print_with_pager(table, JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
}

#define UPDATE_PROGRESS_FAILED INT_MIN
/* Make sure it doesn't overlap w/ errno values */
assert_cc(UPDATE_PROGRESS_FAILED < -ERRNO_MAX);

static void draw_progress_bar(const char *target, unsigned progress, size_t max_target_len, bool wide) {
        _cleanup_free_ char *status = NULL;
        unsigned wide_width, width, filled, i;
        unsigned wide_75, wide_100;

        assert(progress < 100); /* Once we hit 100%, we render a check instead */

        if (asprintf(&status, "%u%% %s", progress, target) < 0) {
                log_oom_debug();
                return;
        }

        if (!colors_enabled() || columns() < 25) {
                fputs(status, stdout);
                return;
        }

        wide_75 = (3 * columns()) / 4;
        wide_100 = columns() - (wide ? strlen(status) : STRLEN("XX% TOTAL")) - 1;
        wide_width = MIN(wide_75, wide_100);

        max_target_len += STRLEN("XX% ");
        if (wide)
                width = wide_width;
        else if (max_target_len < wide_width)
                width = wide_width - max_target_len - 1;
        else
                width = 0;
        filled = (progress * width) / 100;

        if (width < 5) {
                fputs(status, stdout);
                return;
        }

        for (i = 0; i < filled; i++)
                if (i == 0)
                        fputs(special_glyph(SPECIAL_GLYPH_PROGRESS_FILL_START), stdout);
                else if (i == width - 1)
                        fputs(special_glyph(SPECIAL_GLYPH_PROGRESS_FILL_END), stdout);
                else
                        fputs(special_glyph(SPECIAL_GLYPH_PROGRESS_FILL), stdout);
        fputs(ansi_grey(), stdout);
        for (; i < width; i++)
                if (i == 0)
                        fputs(special_glyph(SPECIAL_GLYPH_PROGRESS_EMPTY_START), stdout);
                else if (i == width - 1)
                        fputs(special_glyph(SPECIAL_GLYPH_PROGRESS_EMPTY_END), stdout);
                else
                        fputs(special_glyph(SPECIAL_GLYPH_PROGRESS_EMPTY), stdout);
        fputs(ansi_normal(), stdout);

        fputc(' ', stdout);
        fputs(status, stdout);
}

static int update_render_progress(sd_event_source *source, void *userdata) {
        Hashmap *map = ASSERT_PTR(userdata);
        const char *target;
        void *p;
        unsigned total;
        size_t n, max_target_len = 0;
        bool exiting;

        exiting = sd_event_get_state(sd_event_source_get_event(source)) == SD_EVENT_EXITING;

        total = 0;
        n = hashmap_size(map);

        if (n == 0)
                return 0;

        if (colors_enabled()) {
                for (size_t i = 0; i < n; i++)
                        fputs("\n", stdout); /* Possibly scroll the terminal to make room */
                fprintf(stdout, "\x1B[%zuF", n); /* Go back */

                fputs("\x1B""7", stdout); /* Save cursor position */
                fputs("\x1B[?25l", stdout); /* Hide cursor */
        }

        HASHMAP_FOREACH_KEY(p, target, map)
                max_target_len = MAX(max_target_len, strlen(target));

        HASHMAP_FOREACH_KEY(p, target, map) {
                int progress = PTR_TO_INT(p);

                if (colors_enabled())
                        fputs(ANSI_ERASE_TO_END_OF_LINE, stdout);

                if (progress == UPDATE_PROGRESS_FAILED) {
                        fprintf(stdout, "%s %s\n", RED_CROSS_MARK(), target);
                        total += 100;
                } else if (progress == -EALREADY) {
                        fprintf(stdout, "%s %s (Already up-to-date)\n", GREEN_CHECK_MARK(), target);
                        n--; /* Don't consider this target in the total */
                } else if (progress < 0) {
                        fprintf(stdout, "%s %s (%s)\n", RED_CROSS_MARK(), target, STRERROR(progress));
                        total += 100;
                } else if (progress >= 100) {
                        fprintf(stdout, "%s %s\n", GREEN_CHECK_MARK(), target);
                        total += progress;
                } else {
                        draw_progress_bar(target, progress, max_target_len, n == 1);
                        fputs("\n", stdout);
                        total += progress;
                }
        }

        if (n > 1) {
                if (colors_enabled())
                        fputs(ANSI_ERASE_TO_END_OF_LINE, stdout);
                if (!exiting) {
                        draw_progress_bar("TOTAL", total / n, max_target_len, true);
                        if (!colors_enabled())
                                fputs("\n", stdout);
                }
        }

        if (colors_enabled()) {
                if (exiting)
                        fputs("\x1B[?25h", stdout); /* Show cursor again */
                else
                        fputs("\x1B""8", stdout); /* Restore cursor position */
        } else if (!exiting)
                fputs("------\n", stdout);

        fflush(stdout);
        return 0;
}

static int update_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Userdata *data = ASSERT_PTR(userdata);
        Hashmap *map = ASSERT_PTR(data->userdata);
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

        r = hashmap_replace(map, data->target_id, INT_TO_PTR((int) progress));
        if (r < 0)
                log_debug_errno(r, "Failed to update hashmap: %m");
        return 0;
}

static int update_finished(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        Hashmap *map = ASSERT_PTR(data->userdata);
        uint64_t id;
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

        r = hashmap_replace(map, data->target_id, INT_TO_PTR(status));
        if (r < 0)
                log_debug_errno(r, "Failed to update hashmap: %m");
        return 0;
}

static int update_interrupted(sd_event_source *source, void *userdata) {
        /* Since the event loop is exiting, we will never recieve the JobRemoved
         * signal. So, we must free the userdata here. */
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Hashmap *map = ASSERT_PTR(data->userdata);
        int r;

        r = sd_bus_call_method(data->bus,
                               data->target->destination,
                               data->job_path,
                               "org.freedesktop.sysupdate1.Job",
                               "Cancel",
                               &error, /* reply= */ NULL,
                               NULL);
        if (r < 0)
                return log_bus_error(r, &error, NULL, "call Cancel");

        r = hashmap_replace(map, data->target_id, INT_TO_PTR(-ECANCELED));
        if (r < 0)
                log_debug_errno(r, "Failed to update hashmap: %m");

        return 0;
}

static int update_started(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(userdata_freep) Userdata *data = ASSERT_PTR(userdata);
        Hashmap *map = ASSERT_PTR(data->userdata);
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
                r = hashmap_put(map, key, INT_TO_PTR(r));
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
        assert(!isempty(new_version));

        /* Register this job into the hashmap. This will give it a progress bar */
        if (strchr(data->target_id, '@'))
                key = strdup(data->target_id);
        else
                key = strjoin(data->target_id, "@", new_version);
        if (!key)
                return log_oom();
        r = hashmap_put(map, key, INT_TO_PTR(0)); /* takes ownership of key */
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
                                      data->target->destination,
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
        _cleanup_hashmap_free_ Hashmap *map = NULL;
        _cleanup_strv_free_ char **targets = NULL, **versions = NULL;
        BusLocator **objects = NULL;
        size_t n;
        unsigned remaining = 0;
        void *p;
        bool did_anything = false;
        int r;

        CLEANUP_ARRAY(objects, n, parse_targets_free);

        r = ensure_targets(bus, argv + 1, &targets);
        if (r < 0)
                return r;

        r = parse_targets(targets, &n, &objects, &versions);
        if (r < 0)
                return r;

        map = hashmap_new(&string_hash_ops_free);
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
                u = userdata_new(map, bus, &remaining, objects[i], targets[i]);
                if (!u)
                        return log_oom();

                r = bus_call_method_async(bus, NULL, objects[i], "Update", update_started, u,
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

        HASHMAP_FOREACH(p, map) {
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
                else
                        log_info("Nothing was updated... skipping reboot.");
        }

        return 0;
}

static int verb_vacuum(int argc, char **argv, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **targets = NULL;
        BusLocator **objects = NULL;
        size_t n;
        int r;

        CLEANUP_ARRAY(objects, n, parse_targets_free);

        r = ensure_targets(bus, argv + 1, &targets);
        if (r < 0)
                return r;

        r = parse_targets(targets, &n, &objects, /* ret_versions= */ NULL);
        if (r < 0)
                return r;

        for (size_t i = 0; i < n; i++) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                unsigned count;

                r = bus_call_method(bus, objects[i], "Vacuum", &error, &reply, NULL);
                if (r < 0)
                        return log_bus_error(r, &error, targets[i], "call Vacuum");

                r = sd_bus_message_read(reply, "u", &count);
                if (r < 0)
                        return bus_log_parse_error(r);

                printf("Deleted %u instance(s) of %s.\n", count, targets[i]);
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

        signal(SIGWINCH, columns_lines_cache_reset);

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
