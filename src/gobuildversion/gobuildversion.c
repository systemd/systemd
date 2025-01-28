/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "ansi-color.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "verbs.h"
#include "go_library.h"


static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-gobuildversion", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] COMMAND ...\n"
               "\n%5$sDisplay go build version%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  version                Sign the given binary for EFI Secure Boot\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}


static int verb_version(int argc, char *argv[], void *userdata) {
        GoBuildVersion();
        return 0;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",         VERB_ANY, VERB_ANY, 0,    help              },
                { "version",      1,        1,        0,    verb_version         },
                {}
        };

        log_setup();

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
