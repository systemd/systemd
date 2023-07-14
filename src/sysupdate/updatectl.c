/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>

#include "sd-bus.h"

#include "build.h"
#include "bus-error.h"
#include "bus-label.h"
#include "bus-locator.h"
#include "format-table.h"
#include "main-func.h"
#include "pager.h"
#include "pretty-print.h"
#include "sysupdate-update-set-flags.h"
#include "terminal-util.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_reboot = false;
static bool arg_offline = false;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;

/*typedef struct Context {
        sd_event event;
} Context;

typedef struct Version {
        UpdateSetFlags flags;
} Version;

static BusLocator *job_locator_new(const uint64_t *id) {
        // TODO: Do we need this?
        _cleanup_free_ char *objpath = NULL;

        if (asprintf(&objpath, "/org/freedesktop/sysupdate1/job/_%" PRIu64, id) < 0)
                return NULL;

        return bus_locator_new(bus_sysupdate_mgr.destination,
                               "org.freedesktop.sysupdate1.Job",
                               objpath);
}*/

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
                        _cleanup_(bus_locator_freep) BusLocator *object = NULL;
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
                                               "Unexpected version specifier in argument: %s",
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

static int list_targets(sd_bus *bus) {
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

        STRV_FOREACH(id, targets)
                log_info("ID: %s", *id);

        // TODO: Present the targets in a table
        // Columns:
        //      ID: targets[i]
        //      Version: bus_get_property(objects[i], "Version")
        //      Path: bus_get_property(objects[i], "Path")
        return 0;
}

static int list_versions(sd_bus *bus, BusLocator *object) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

        // TODO: Call List() on the bus
        // TODO: Display the results in a table
        log_info("%s: List(offline=%s)", object->path, true_false(arg_offline));
        return 0;
}

static int describe(sd_bus *bus, BusLocator *object, const char *version) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

        // TODO: Call Describe() on the bus
        // TODO: Display the results in a table
        log_info("%s: Describe(version=%s, offline=%s)", object->path, version, true_false(arg_offline));
        return 0;
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

static int verb_check(int argc, char **argv, void *userdata) {
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

        // TODO: Present the targets in a table
        // Columns:
        //      ID: targets[i]
        //      Update: printf("%s -> %s", bus_get_property(objects[i], "Version"), bus_call_method(objects[i], "CheckNew"))

        log_info("CheckNew() reboot=%s offline=%s argv=[%s]",
                        true_false(arg_reboot),
                        true_false(arg_offline),
                        strv_join(argv, ", "));
        return 0;
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
                // TODO
                log_info("%s: Vacuum()", objects[i]->path);
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
                { "vacuum", VERB_ANY, 2,        VERB_ONLINE_ONLY,              verb_vacuum   },
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
