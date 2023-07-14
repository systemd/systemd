/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>

#include "sd-bus.h"

#include "build.h"
#include "bus-error.h"
#include "bus-label.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "format-table.h"
#include "json.h"
#include "main-func.h"
#include "pager.h"
#include "pretty-print.h"
#include "string-table.h"
#include "sysupdate-update-set-flags.h"
#include "terminal-util.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_reboot = false;
static bool arg_offline = false;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;

/*
static BusLocator *job_locator_new(const uint64_t *id) {
        // TODO: Do we need this?
        _cleanup_free_ char *objpath = NULL;

        if (asprintf(&objpath, "/org/freedesktop/sysupdate1/job/_%" PRIu64, id) < 0)
                return NULL;

        return bus_locator_new(bus_sysupdate_mgr.destination,
                               "org.freedesktop.sysupdate1.Job",
                               objpath);
}*/

typedef struct Version {
        char *version;
        UpdateSetFlags flags;
        char *contents_json;
} Version;

static void version_clear(Version *v) {
        if (!v)
                return;

        v->version = mfree(v->version);
        v->flags = 0;
        v->contents_json = mfree(v->contents_json);
}

typedef struct AsyncUserdata {
        void *userdata;
        size_t remaining;
} AsyncUserdata;

typedef struct TargetAsyncUserdata {
        AsyncUserdata *async;
        BusLocator *target;
        const char *target_id;
} TargetAsyncUserdata;

static int async_userdata_wait(sd_bus *bus, AsyncUserdata *wait) {
        int r;

        while (wait->remaining) {
                r = sd_bus_process(bus, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to process requests: %m");
                if (r > 0)
                        continue;

                r = sd_bus_wait(bus, UINT64_MAX);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait: %m");
        }
        return 0;
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
                        _cleanup_free_ char *id;

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
                { "version",   "s", NULL,              offsetof(Version, version) },
                { "newest",    "b", map_version_flags, offsetof(Version, flags) },
                { "available", "b", map_version_flags, offsetof(Version, flags) },
                { "installed", "b", map_version_flags, offsetof(Version, flags) },
                { "obsolete",  "b", map_version_flags, offsetof(Version, flags) },
                { "protected", "b", map_version_flags, offsetof(Version, flags) },
                { "_contents", "s", NULL,              offsetof(Version, contents_json) },
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
        AsyncUserdata *async = ASSERT_PTR(userdata);
        Table *table = ASSERT_PTR(async->userdata);
        sd_bus *bus;
        const sd_bus_error *e;
        _cleanup_(version_clear) Version v = {};
        const char *color;
        int r;

        assert(reply);
        assert_se(bus = sd_bus_message_get_bus(reply));

        async->remaining--;

        e = sd_bus_message_get_error(reply);
        if (e)
                return log_bus_error(0, e, NULL, "call Describe");

        r = parse_describe(reply, &v);
        if (r < 0)
                return r;

        color = update_set_flags_to_color(v.flags);

        r = table_add_many(table,
                           TABLE_STRING,    update_set_flags_to_glyph(v.flags),
                           TABLE_SET_COLOR, color,
                           TABLE_STRING,    v.version,
                           TABLE_SET_COLOR, color,
                           TABLE_STRING,    update_set_flags_to_string(v.flags),
                           TABLE_SET_COLOR, color);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int list_versions(sd_bus *bus, BusLocator *target) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **versions = NULL;
        AsyncUserdata async;
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

        async = (AsyncUserdata) { table };

        STRV_FOREACH(version, versions) {
                r = bus_call_method_async(bus, NULL, target, "Describe", list_versions_finished, &async,
                                          "sb", *version, arg_offline);
                if (r < 0)
                        return r;

                async.remaining++;
        }

        r = async_userdata_wait(bus, &async);
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

        printf("%s%s%s Version: %s\n"
               "  State: %s%s%s\n"
               "\n",
               color, update_set_flags_to_glyph(v.flags), ansi_normal(), v.version,
               color, update_set_flags_to_string(v.flags), ansi_normal());

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
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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

static int check_finished(sd_bus_message *reply, void *_userdata, sd_bus_error *ret_error) {
        TargetAsyncUserdata *userdata = ASSERT_PTR(_userdata);
        Table *table = ASSERT_PTR(userdata->async->userdata);
        BusLocator *target = ASSERT_PTR(userdata->target);
        const char *target_id = ASSERT_PTR(userdata->target_id);
        sd_bus *bus;
        const sd_bus_error *e;
        _cleanup_free_ char *version = NULL, *update = NULL;
        const char *new_version = NULL;
        int r;

        assert(reply);
        assert_se(bus = sd_bus_message_get_bus(reply));

        userdata->async->remaining--;

        e = sd_bus_message_get_error(reply);
        if (e)
                return log_bus_error(0, e, target_id, "call CheckNew");

        r = sd_bus_message_read(reply, "s", &new_version);
        if (r < 0)
                return bus_log_parse_error(r);

        if (isempty(new_version))
                return 0;

        r = bus_get_property_string(bus, target, "Version", ret_error, &version);
        if (r < 0)
                return log_bus_error(r, ret_error, target_id, "get Version");

        update = strjoin(version, " ", special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), " ", new_version);
        if (!update)
                return log_oom();

        r = table_add_many(table,
                           TABLE_STRING, target_id,
                           TABLE_STRING, update);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int verb_check(int argc, char **argv, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **targets = NULL;
        BusLocator **objects = NULL;
        size_t n;
        AsyncUserdata async;
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

        async = (AsyncUserdata) { table };

        for (size_t i = 0; i < n; i++) {
                TargetAsyncUserdata t = (TargetAsyncUserdata) {
                        .async = &async,
                        .target = objects[i],
                        .target_id = targets[i],
                };

                r = bus_call_method_async(bus, NULL, objects[i], "CheckNew", check_finished, &t, NULL);
                if (r < 0)
                        return r;

                async.remaining++;
        }

        r = async_userdata_wait(bus, &async);
        if (r < 0)
                return r;

        return table_print_with_pager(table, JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
}

static int verb_update(int argc, char **argv, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **targets = NULL, **versions = NULL;
        BusLocator **objects = NULL;
        size_t n;
        int r;

        CLEANUP_ARRAY(objects, n, parse_targets_free);

        r = ensure_targets(bus, argv + 1, &targets);
        if (r < 0)
                return r;

        r = parse_targets(targets, &n, &objects, &versions);
        if (r < 0)
                return r;

        // TODO: Figure out event loop & progress

        for (size_t i = 0; i < n; i++) {
                // TODO
                log_info("%s: Update(version=%s)", objects[i]->path, versions[i]);
        }

        // TODO
        if (arg_reboot)
                log_info("Reboot...");

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
               "  vacuum [TARGET...]            Cleanup old updates\n"
               "  -h --help                     Show this help\n"
               "     --version                  Show package version\n"

               "  list [VERSION]          Show installed and available versions\n"
               "  check-new               Check if there's a new version available\n"
               "  update [VERSION]        Install new version now\n"
               "  vacuum                  Make room, by deleting old versions\n"
               "  pending                 Report whether a newer version is installed than\n"
               "                          currently booted\n"
               "  reboot                  Reboot if a newer version is installed than booted\n"
               "  components              Show list of components\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "\n%3$sOptions:%4$s\n"
               "     --reboot             Reboot after updating to newer version\n"
               "     --offline            Do not fetch metadata from the network\n"
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
                { "machine",   required_argument, NULL, 'M'             },
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

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
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

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, RUNTIME_SCOPE_SYSTEM, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        return dispatch_verb(argc, argv, verbs, bus);
}

DEFINE_MAIN_FUNCTION(run);
