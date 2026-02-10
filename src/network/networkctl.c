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

#include "networkctl.args.inc"

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
               OPTION_HELP_GENERATED
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
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
                { "renew",              2,        VERB_ANY, VERB_ONLINE_ONLY,              link_renew              },
                { "forcerenew",         2,        VERB_ANY, VERB_ONLINE_ONLY,              link_force_renew        },
                { "reconfigure",        2,        VERB_ANY, VERB_ONLINE_ONLY,              verb_reconfigure        },
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

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

        journal_browse_prepare();

        return networkctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
