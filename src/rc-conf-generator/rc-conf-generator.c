/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "ansi-color.h"
#include "build.h"
#include "copy.h"
#include "efi-fundamental.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "pe-binary.h"
#include "pretty-print.h"
#include "stat-util.h"
#include "tmpfile-util.h"
#include "verbs.h"
#include "go_library.h"


static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-rc-conf-generator", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] COMMAND ...\n"
               "\n%5$sCreate systemd services from rc.conf%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  generate                Read an rc.conf file and create services\n"
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
        GenerateRCConf();
        return 0;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",         VERB_ANY, VERB_ANY, 0,    help              },
                { "generate",      1,        1,        0,    verb_version         },
                {}
        };

        log_setup();

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
