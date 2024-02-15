/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "bpf-dlopen.h"
#include "bpfd-manager.h"
#include "build.h"
#include "format-table.h"
#include "json-util.h"
#include "main-func.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "strv.h"
#include "varlink.h"
#include "verbs.h"

static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;

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

static void bpf_program_data_done(BpfProgramData *p) {
        assert(p);

        p->name = mfree(p->name);
        p->tag = mfree(p->tag);
        strv_free(p->map_names);
}

static void bpf_map_data_done(BpfMapData *p) {
        assert(p);

        p->name = mfree(p->name);
}

static int query_and_print_bpf_maps(void) {
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        _cleanup_(table_unrefp) Table *map_table = NULL;
        sd_json_variant *i = NULL, *o = NULL;
        int r;

        map_table = table_new("name", "type", "memlock");
        if (!map_table)
                return log_oom();

        r = varlink_connect_address(&vl, BPFD_VARLINK_ADDRESS);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to varlink address %s: %m", BPFD_VARLINK_ADDRESS);

        r = varlink_collect_full(vl, "io.systemd.Bpf.DescribeMaps", i, &o, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to collect varlink method: %m");

        JSON_VARIANT_ARRAY_FOREACH(i, o) {
                static const sd_json_dispatch_field dispatch_table[] = {
                        { "name",    SD_JSON_VARIANT_STRING,   sd_json_dispatch_string, offsetof(struct BpfMapData, name),    SD_JSON_MANDATORY },
                        { "type",    SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint64, offsetof(struct BpfMapData, type),    SD_JSON_MANDATORY },
                        { "memlock", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint64, offsetof(struct BpfMapData, memlock), SD_JSON_MANDATORY },
                        {}
                };
                _cleanup_(bpf_map_data_done) BpfMapData p = {};
                const char *map_type = NULL;

                r = sd_json_dispatch(i, dispatch_table, 0, &p);
                if (r < 0)
                        return log_error_errno(r, "Failed to dispatch map table: %m");

                if (!sym_libbpf_bpf_map_type_str)
                        log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libbpf too old to translate bpf_map_type enum to string. Printing out enum directly");
                else {
                        map_type = sym_libbpf_bpf_map_type_str(p.type);
                        if (!map_type)
                                return log_error_errno(r, "Failed to translate bpf_map_type enum %lu to a valid string: %m", p.type);
                }

                if (!map_type)
                        r = table_add_many(map_table,
                                        TABLE_STRING, p.name,
                                        TABLE_UINT64, p.type,
                                        TABLE_SIZE, p.memlock);
                else
                        r = table_add_many(map_table,
                                        TABLE_STRING, p.name,
                                        TABLE_STRING, map_type,
                                        TABLE_SIZE, p.memlock);
                if (r < 0)
                        return log_error_errno(r, "Failed to add to map table: %m");
        }

        r = table_print_with_pager(map_table, arg_json_format_flags, arg_pager_flags, /*show_header*/true);
        if (r < 0)
                return log_error_errno(r, "Failed to output map table: %m");

        return 0;
}

static int query_and_print_bpf_progs(void) {
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        _cleanup_(table_unrefp) Table *prog_table = NULL;
        sd_json_variant *i = NULL, *o = NULL;
        int r;

        prog_table = table_new("name", "type", "memlock", "tag", "map names", "run time ns", "run cnt");
        if (!prog_table)
                return log_oom();

        r = varlink_connect_address(&vl, BPFD_VARLINK_ADDRESS);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to varlink address %s: %m", BPFD_VARLINK_ADDRESS);

        r = varlink_collect_full(vl, "io.systemd.Bpf.DescribePrograms", i, &o, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to collect varlink method: %m");

        JSON_VARIANT_ARRAY_FOREACH(i, o) {
                static const sd_json_dispatch_field dispatch_table[] = {
                        { "name",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(struct BpfProgramData, name),        SD_JSON_MANDATORY },
                        { "type",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct BpfProgramData, type),        SD_JSON_MANDATORY },
                        { "memlock",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct BpfProgramData, memlock),     SD_JSON_MANDATORY },
                        { "tag",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(struct BpfProgramData, tag),         SD_JSON_MANDATORY },
                        { "map_names",   SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,   offsetof(struct BpfProgramData, map_names),   0              },
                        { "run_time_ns", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct BpfProgramData, run_time_ns), SD_JSON_MANDATORY },
                        { "run_count",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct BpfProgramData, run_cnt),     SD_JSON_MANDATORY },
                        {}
                };
                _cleanup_(bpf_program_data_done) BpfProgramData p = {};
                const char *prog_type = NULL;

                r = sd_json_dispatch(i, dispatch_table, 0, &p);
                if (r < 0)
                        return log_error_errno(r, "Failed to dispatch program table: %m");

                if (!sym_libbpf_bpf_prog_type_str)
                        log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libbpf too old to translate bpf_prog_type enum to string. Printing out enum directly");
                else {
                        prog_type = sym_libbpf_bpf_prog_type_str(p.type);
                        if (!prog_type)
                                return log_error_errno(r, "Failed to translate bpf_prog_type enum %lu to a valid string: %m", p.type);
                }

                if (!prog_type)
                        r = table_add_many(prog_table,
                                        TABLE_STRING, p.name,
                                        TABLE_UINT64, p.type,
                                        TABLE_SIZE, p.memlock,
                                        TABLE_STRING, p.tag,
                                        TABLE_STRV, p.map_names,
                                        TABLE_UINT64, p.run_time_ns,
                                        TABLE_UINT64, p.run_cnt);
                else
                        r = table_add_many(prog_table,
                                        TABLE_STRING, p.name,
                                        TABLE_STRING, prog_type,
                                        TABLE_SIZE, p.memlock,
                                        TABLE_STRING, p.tag,
                                        TABLE_STRV, p.map_names,
                                        TABLE_UINT64, p.run_time_ns,
                                        TABLE_UINT64, p.run_cnt);
                if (r < 0)
                        return log_error_errno(r, "Failed to add to program table: %m");
        }

        r = table_print_with_pager(prog_table, arg_json_format_flags, arg_pager_flags, /*show_header*/true);
        if (r < 0)
                return log_error_errno(r, "Failed to output program table: %m");

        return 0;
}

static int verb_list_all(int argc, char *argv[], void *userdata) {
        int r;

        r = query_and_print_bpf_maps();
        if (r < 0)
                return r;

        r = query_and_print_bpf_progs();
        if (r < 0)
                return r;

        return 0;
}

static int verb_list_maps(int argc, char *argv[], void *userdata) {
        int r;

        r = query_and_print_bpf_maps();
        if (r < 0)
                return r;

        return 0;
}

static int verb_list_progs(int argc, char *argv[], void *userdata) {
        int r;

        r = query_and_print_bpf_progs();
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
               "%sQuery running BPF programs and maps.%s\n"
               "\nCommands:\n"
               "  list-all               List all BPF maps and programs\n"
               "  list-maps              List all BPF maps\n"
               "  list-programs          List all BPF programs\n"
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
                ARG_NO_PAGER,
                ARG_JSON,
                ARG_NO_RELOAD,
        };

        static const struct option options[] = {
                { "help",     no_argument,       NULL, 'h'          },
                { "version",  no_argument,       NULL, ARG_VERSION  },
                { "no-pager", no_argument,       NULL, ARG_NO_PAGER },
                { "json",     required_argument, NULL, ARG_JSON     },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hasln:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

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

        return 1;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "list-all",   VERB_ANY, VERB_ANY, VERB_DEFAULT, verb_list_all   },
                { "list-maps",  VERB_ANY, VERB_ANY, 0,            verb_list_maps  },
                { "list-progs", VERB_ANY, VERB_ANY, 0,            verb_list_progs },
                {}
        };

        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = dlopen_bpf();
        if (r < 0)
                return log_error_errno(r, "Couldn't dlopen_bpf: %m");

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
