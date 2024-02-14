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

typedef struct BpfProgramData BpfProgramData;
typedef struct BpfMapData BpfMapData;

struct BpfProgramData {
        char *name;
        uint64_t type;
        uint64_t memlock;
        char *tag;
        char **map_names;
        uint64_t run_time_ns;
        uint64_t run_cnt;
};

struct BpfMapData {
        char *name;
        uint64_t type;
        uint64_t memlock;
};

static void bpf_prog_data_done(BpfProgramData *p) {
        assert(p);

        p->name = mfree(p->name);
        p->tag = mfree(p->tag);
        strv_free(p->map_names);
}

static void bpf_map_data_done(BpfMapData *p) {
        assert(p);

        p->name = mfree(p->name);
}

static int query_bpf_progs_and_maps(void) {
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        _cleanup_(table_unrefp) Table *map_table = NULL, *prog_table = NULL;
        JsonVariant *i = NULL, *o = NULL, *m = NULL, *v = NULL;
        int r;

        map_table = table_new("map_name", "map_type", "memlock");
        if (!map_table)
                return log_oom();

        prog_table = table_new("program_name", "program_type", "memlock", "program_tag", "program_map_names", "run_time_ns", "run_cnt");
        if (!prog_table)
                return log_oom();

        r = varlink_connect_address(&vl, "/run/systemd/bpf/io.systemd.Bpf");
        if (r < 0)
                return log_error_errno(r, "Unable to connect to /run/systemd/bpf/io.systemd.Bpf: %m");

        r = varlink_collect_full(vl, "io.systemd.Bpf.Describe", i, &o, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to collect varlink method: %m");

        JSON_VARIANT_ARRAY_FOREACH(i, o) {
                m = json_variant_by_key(i, "type");
                if (!m)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to find type field of json variant");
                v = json_variant_by_key(i, "data");
                if (!v)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to find data field of json variant");

                if (streq(json_variant_string(m), "map")) {
                        static const JsonDispatch dispatch_table[] = {
                                { "name",  JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct BpfMapData, name),  JSON_MANDATORY },
                                { "type", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct BpfMapData, type), JSON_MANDATORY},
                                { "memlock", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct BpfMapData, memlock), JSON_MANDATORY},
                                {}
                        };
                        _cleanup_(bpf_map_data_done) BpfMapData p = {};

                        r = json_dispatch(v, dispatch_table, 0, &p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to dispatch map table: %m");

                        r = table_add_many(map_table,
                                   TABLE_STRING, p.name, TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_UINT64, p.type, TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_UINT64, p.memlock, TABLE_SET_ALIGN_PERCENT, 100);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add to map table: %m");
                } else {
                        static const JsonDispatch dispatch_table[] = {
                                { "name",  JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct BpfProgramData, name),  JSON_MANDATORY },
                                { "type", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct BpfProgramData, type), JSON_MANDATORY},
                                { "memlock", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct BpfProgramData, memlock), JSON_MANDATORY},
                                { "tag", JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct BpfProgramData, tag), JSON_MANDATORY},
                                { "map_names", JSON_VARIANT_ARRAY, json_dispatch_strv, offsetof(struct BpfProgramData, map_names), 0},
                                { "run_time_ns", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct BpfProgramData, run_time_ns), JSON_MANDATORY},
                                { "run_count", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct BpfProgramData, run_cnt), JSON_MANDATORY},
                                {}
                        };
                        _cleanup_(bpf_prog_data_done) BpfProgramData p = {};

                        r = json_dispatch(v, dispatch_table, 0, &p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to dispatch program table: %m");

                        r = table_add_many(prog_table,
                                   TABLE_STRING, p.name, TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_UINT64, p.type, TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_UINT64, p.memlock, TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_STRING, p.tag, TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_STRV, p.map_names, TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_UINT64, p.run_time_ns, TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_UINT64, p.run_cnt, TABLE_SET_ALIGN_PERCENT, 100);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add to program table: %m");
                }
        }

        r = table_print(map_table, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to output map table: %m");

        r = table_print(prog_table, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to output program table: %m");

        return 0;
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
