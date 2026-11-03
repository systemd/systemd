/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "dlopen-note.h"
#include "fs-util.h"
#include "label-util.h"
#include "log.h"
#include "main-func.h"
#include "reboot-util.h"
#include "verbs.h"

COMMAND(
        "systemd-user-sessions\0",
        "Permit user logins after boot, prohibit them at shutdown.",
        .man_pages = "systemd-user-sessions.service(8)\0",
        .option_namespace = "common",
);

/* We only touch /run/nologin. See create_shutdown_run_nologin_or_warn() for details. */

VERB_NOARG(verb_start, "start", "Permit user logins");
static int verb_start(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return unlink_or_warn("/run/nologin");
}

VERB_NOARG(verb_stop, "stop", "Prohibit user logins");
static int verb_stop(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return create_shutdown_run_nologin_or_warn();
}

static int run(int argc, char *argv[]) {
        int r;

        LIBSELINUX_NOTE(recommended);

        log_setup();

        char **args = NULL;
        r = common_parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        umask(0022);

        r = mac_init();
        if (r < 0)
                return r;

        return dispatch_verb(args, /* userdata= */ NULL);
}

DEFINE_MAIN_FUNCTION(run);
