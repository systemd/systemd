/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "logs-show.h"
#include "main-func.h"
#include "networkctl.h"
#include "networkctl-address-label.h"
#include "networkctl-config-file.h"
#include "networkctl-list.h"
#include "networkctl-lldp.h"
#include "networkctl-misc.h"
#include "networkctl-status-link.h"
#include "options.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "verbs.h"

PagerFlags arg_pager_flags = 0;
bool arg_legend = true;
bool arg_no_reload = false;
bool arg_all = false;
bool arg_stats = false;
bool arg_full = false;
bool arg_runtime = false;
bool arg_stdin = false;
unsigned arg_lines = 10;
char *arg_drop_in = NULL;
sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
bool arg_ask_password = true;

STATIC_DESTRUCTOR_REGISTER(arg_drop_in, freep);

VERB_SCOPE(, verb_list_links,                 "list",               "[PATTERN...]",  VERB_ANY, VERB_ANY, VERB_DEFAULT|VERB_ONLINE_ONLY,
           "List links");
VERB_SCOPE(, verb_link_status,                "status",             "[PATTERN...]",  VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Show link status");
VERB_SCOPE(, verb_link_lldp_status,           "lldp",               "[PATTERN...]",  VERB_ANY, VERB_ANY, 0,
           "Show LLDP neighbors");
VERB_SCOPE(, verb_list_address_labels,        "label",              NULL,            1,        1,        0,
           "Show current address label entries in the kernel");
VERB_SCOPE(, verb_link_delete,                "delete",             "DEVICES...",    2,        VERB_ANY, 0,
           "Delete virtual netdevs");
VERB_SCOPE(, verb_link_varlink_simple_method, "up",                 "DEVICES...",    2,        VERB_ANY, 0,
           "Bring devices up");
VERB_SCOPE(, verb_link_varlink_simple_method, "down",               "DEVICES...",    2,        VERB_ANY, 0,
           "Bring devices down");
VERB_SCOPE(, verb_link_varlink_simple_method, "renew",              "DEVICES...",    2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Renew dynamic configurations");
VERB_SCOPE(, verb_link_varlink_simple_method, "forcerenew",         "DEVICES...",    2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Trigger DHCP reconfiguration of all connected clients");
VERB_SCOPE(, verb_link_varlink_simple_method, "reconfigure",        "DEVICES...",    2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Reconfigure interfaces");
VERB_SCOPE(, verb_reload,                     "reload",             NULL,            1,        1,        VERB_ONLINE_ONLY,
           "Reload .network and .netdev files");
VERB_SCOPE(, verb_edit,                       "edit",               "FILES|DEVICES...",   2,   VERB_ANY, 0,
           "Edit network configuration files");
VERB_SCOPE(, verb_cat,                        "cat",                "[FILES|DEVICES...]", 1,   VERB_ANY, 0,
           "Show network configuration files");
VERB_SCOPE(, verb_mask,                       "mask",               "FILES...",      2,        VERB_ANY, 0,
           "Mask network configuration files");
VERB_SCOPE(, verb_unmask,                     "unmask",             "FILES...",      2,        VERB_ANY, 0,
           "Unmask network configuration files");
VERB_SCOPE(, verb_persistent_storage,         "persistent-storage", "BOOL",          2,        2,        0,
           "Notify systemd-networkd if persistent storage is ready");

static int help(void) {
        _cleanup_(table_unrefp) Table *verbs = NULL, *options = NULL;
        int r;

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        help_cmdline("[OPTIONS...] COMMAND");
        help_abstract("Query and control the networking subsystem.");

        help_section("Commands");
        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("networkctl", "1");
        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                OPTION('a', "all", NULL, "Show status for all links"):
                        arg_all = true;
                        break;

                OPTION('s', "stats", NULL, "Show detailed link statistics"):
                        arg_stats = true;
                        break;

                OPTION('l', "full", NULL, "Do not ellipsize output"):
                        arg_full = true;
                        break;

                OPTION('n', "lines", "INTEGER", "Number of journal entries to show"):
                        r = safe_atou(opts.arg, &arg_lines);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --lines value '%s': %m", opts.arg);
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("no-reload", NULL,
                            "Do not reload systemd-networkd or systemd-udevd after editing network config"):
                        arg_no_reload = true;
                        break;

                OPTION_LONG("drop-in", "NAME",
                            "Edit specified drop-in instead of main config file"):
                        if (isempty(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty drop-in file name.");

                        if (!endswith(opts.arg, ".conf")) {
                                char *conf;

                                conf = strjoin(opts.arg, ".conf");
                                if (!conf)
                                        return log_oom();

                                free_and_replace(arg_drop_in, conf);
                        } else {
                                r = free_and_strdup(&arg_drop_in, opts.arg);
                                if (r < 0)
                                        return log_oom();
                        }

                        if (!filename_is_valid(arg_drop_in))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid drop-in file name '%s'.", arg_drop_in);

                        break;

                OPTION_LONG("runtime", NULL, "Edit runtime config files"):
                        arg_runtime = true;
                        break;

                OPTION_LONG("stdin", NULL, "Read new contents of edited file from stdin"):
                        arg_stdin = true;
                        break;
                }

        *remaining_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char* argv[]) {
        char **args = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        journal_browse_prepare();

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
