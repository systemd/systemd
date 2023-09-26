/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "build.h"
#include "format-table.h"
#include "format-util.h"
#include "main-func.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "varlink.h"
#include "verbs.h"

static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;

struct bpf_prog_data {
        char *name;
        uint64_t type;
        char *memlock;
        char *tag;
        char *map_names;
        uint64_t run_time_ns;
        uint64_t run_cnt;
};

struct bpf_map_data {
        char *name;
        uint64_t type;
        char *memlock;
};

static int query_bpf_progs_and_maps_reply(
                Varlink *link,
                JsonVariant *parameters,
                const char *error_id,
                VarlinkReplyFlags flags,
                void *userdata) {

        int r;
        JsonVariant *m, *v;

        // json_variant_dump(parameters, JSON_FORMAT_PRETTY, NULL, NULL);

        m = json_variant_by_key(parameters, "TYPE");
        if (!m)
                return 0;
        v = json_variant_by_key(parameters, "DATA");
        if (!v)
                return 0;

        if (streq(json_variant_string(m), "MAP")) {
                static const JsonDispatch dispatch_table[] = {
                        { "NAME",  JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct bpf_map_data, name),  JSON_MANDATORY },
                        { "TYPE", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct bpf_map_data, type), JSON_MANDATORY},
                        { "MEMLOCK", JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct bpf_map_data, memlock), JSON_MANDATORY},
                        {}
                };
                struct bpf_map_data p = {};

                r = json_dispatch(v, dispatch_table, NULL, 0, &p);
                if (r < 0)
                        return r;

                log_info(" map_name: %s, map_type: %lu, memlock: %s", p.name, p.type, p.memlock);
        } else {
                static const JsonDispatch dispatch_table[] = {
                        { "NAME",  JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct bpf_prog_data, name),  JSON_MANDATORY },
                        { "TYPE", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct bpf_prog_data, type), JSON_MANDATORY},
                        { "MEMLOCK", JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct bpf_prog_data, memlock), JSON_MANDATORY},
                        { "TAG", JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct bpf_prog_data, tag), JSON_MANDATORY},
                        { "MAP_NAMES", JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct bpf_prog_data, map_names), 0},
                        { "RUN_TIME_NS", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct bpf_prog_data, run_time_ns), JSON_MANDATORY},
                        { "RUN_COUNT", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct bpf_prog_data, run_cnt), JSON_MANDATORY},
                        {}
                };
                struct bpf_prog_data p = {
                        .map_names = NULL,
                };

                r = json_dispatch(v, dispatch_table, NULL, 0, &p);
                if (r < 0)
                        return r;

                log_info(" prog_name: %s, prog_type: %lu, memlock: %s, prog_tag: %s, prog_map_names: %s, run_time_ns: %lu, run_cnt: %lu", p.name, p.type, p.memlock, p.tag, p.map_names, p.run_time_ns, p.run_cnt);
        }

        return 0;
}

static int query_bpf_progs_and_maps(void) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        int r;

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = varlink_connect_address(&vl, "/run/systemd/bpf/io.systemd.Bpf");
        if (r < 0)
                return log_debug_errno(r, "Unable to connect to /run/systemd/bpf/io.systemd.Bpf: %m");

        r = varlink_attach_event(vl, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = varlink_bind_reply(vl, query_bpf_progs_and_maps_reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to bind reply callback: %m");
        char method[] = "io.systemd.BpfProgsAndMaps.GetBpfProgsAndMaps";
        r = varlink_observe(vl, method, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to invoke varlink method: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");
        return r;
}

static int verb_list(int argc, char *argv[], void *userdata) {
        int r;

        r = query_bpf_progs_and_maps();
        if (r < 0)
                return r;
        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("bpfctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND\n\n"
               "%sQuery running bpf programs and maps.%s\n"
               "\nCommands:\n"
               "  list                   List all bpf maps and programs\n"
               "\nOptions:\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --json=pretty|short|off\n"
               "                         Generate JSON output\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_JSON,
                ARG_NO_RELOAD,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "json",      required_argument, NULL, ARG_JSON      },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hasln:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
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
        static const Verb verbs[] = {
                { "list", VERB_ANY, VERB_ANY, VERB_DEFAULT, verb_list },
                {}
        };

        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
