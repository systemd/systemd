/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
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
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
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

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("networkctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND\n\n"
               "%sQuery and control the networking subsystem.%s\n"
               "\nCommands:\n"
               "  list [PATTERN...]      List links\n"
               "  status [PATTERN...]    Show link status\n"
               "  lldp [PATTERN...]      Show LLDP neighbors\n"
               "  label                  Show current address label entries in the kernel\n"
               "  delete DEVICES...      Delete virtual netdevs\n"
               "  up DEVICES...          Bring devices up\n"
               "  down DEVICES...        Bring devices down\n"
               "  renew DEVICES...       Renew dynamic configurations\n"
               "  forcerenew DEVICES...  Trigger DHCP reconfiguration of all connected clients\n"
               "  reconfigure DEVICES... Reconfigure interfaces\n"
               "  reload                 Reload .network and .netdev files\n"
               "  edit FILES|DEVICES...  Edit network configuration files\n"
               "  cat [FILES|DEVICES...] Show network configuration files\n"
               "  mask FILES...          Mask network configuration files\n"
               "  unmask FILES...        Unmask network configuration files\n"
               "  persistent-storage BOOL\n"
               "                         Notify systemd-networkd if persistent storage is ready\n"
               "\nOptions:\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --no-legend         Do not show the headers and footers\n"
               "     --no-ask-password   Do not prompt for password\n"
               "  -a --all               Show status for all links\n"
               "  -s --stats             Show detailed link statistics\n"
               "  -l --full              Do not ellipsize output\n"
               "  -n --lines=INTEGER     Number of journal entries to show\n"
               "     --json=pretty|short|off\n"
               "                         Generate JSON output\n"
               "     --no-reload         Do not reload systemd-networkd or systemd-udevd\n"
               "                         after editing network config\n"
               "     --drop-in=NAME      Edit specified drop-in instead of main config file\n"
               "     --runtime           Edit runtime config files\n"
               "     --stdin             Read new contents of edited file from stdin\n"
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
                ARG_NO_LEGEND,
                ARG_NO_ASK_PASSWORD,
                ARG_JSON,
                ARG_NO_RELOAD,
                ARG_DROP_IN,
                ARG_RUNTIME,
                ARG_STDIN,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "no-legend",       no_argument,       NULL, ARG_NO_LEGEND       },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { "all",             no_argument,       NULL, 'a'                 },
                { "stats",           no_argument,       NULL, 's'                 },
                { "full",            no_argument,       NULL, 'l'                 },
                { "lines",           required_argument, NULL, 'n'                 },
                { "json",            required_argument, NULL, ARG_JSON            },
                { "no-reload",       no_argument,       NULL, ARG_NO_RELOAD       },
                { "drop-in",         required_argument, NULL, ARG_DROP_IN         },
                { "runtime",         no_argument,       NULL, ARG_RUNTIME         },
                { "stdin",           no_argument,       NULL, ARG_STDIN           },
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

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_NO_RELOAD:
                        arg_no_reload = true;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case ARG_RUNTIME:
                        arg_runtime = true;
                        break;

                case ARG_STDIN:
                        arg_stdin = true;
                        break;

                case ARG_DROP_IN:
                        if (isempty(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty drop-in file name.");

                        if (!endswith(optarg, ".conf")) {
                                char *conf;

                                conf = strjoin(optarg, ".conf");
                                if (!conf)
                                        return log_oom();

                                free_and_replace(arg_drop_in, conf);
                        } else {
                                r = free_and_strdup(&arg_drop_in, optarg);
                                if (r < 0)
                                        return log_oom();
                        }

                        if (!filename_is_valid(arg_drop_in))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid drop-in file name '%s'.", arg_drop_in);

                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 's':
                        arg_stats = true;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case 'n':
                        if (safe_atou(optarg, &arg_lines) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse lines '%s'", optarg);
                        break;

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

static int networkctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "list",               VERB_ANY, VERB_ANY, VERB_DEFAULT|VERB_ONLINE_ONLY, list_links              },
                { "status",             VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,              link_status             },
                { "lldp",               VERB_ANY, VERB_ANY, 0,                             link_lldp_status        },
                { "label",              1,        1,        0,                             list_address_labels     },
                { "delete",             2,        VERB_ANY, 0,                             link_delete             },
                { "up",                 2,        VERB_ANY, 0,                             link_up_down            },
                { "down",               2,        VERB_ANY, 0,                             link_up_down            },
                { "renew",              2,        VERB_ANY, VERB_ONLINE_ONLY,              link_bus_simple_method  },
                { "forcerenew",         2,        VERB_ANY, VERB_ONLINE_ONLY,              link_bus_simple_method  },
                { "reconfigure",        2,        VERB_ANY, VERB_ONLINE_ONLY,              link_bus_simple_method  },
                { "reload",             1,        1,        VERB_ONLINE_ONLY,              verb_reload             },
                { "edit",               2,        VERB_ANY, 0,                             verb_edit               },
                { "cat",                1,        VERB_ANY, 0,                             verb_cat                },
                { "mask",               2,        VERB_ANY, 0,                             verb_mask               },
                { "unmask",             2,        VERB_ANY, 0,                             verb_unmask             },
                { "persistent-storage", 2,        2,        0,                             verb_persistent_storage },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        journal_browse_prepare();

        return networkctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
