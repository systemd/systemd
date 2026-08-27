/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>

#include "ansi-color.h"
#include "help-util.h"
#include "path-util.h"

/* These are helpers for putting together --help texts in a uniform way with a common output style:
 * help_cmdline() outputs a brief summary of the command line syntax, and help_section() formats the
 * headings of the individual sections of the --help text. */

void help_cmdline(const char *arguments) {
        const char *progname =
                last_path_component(secure_getenv("SYSTEMD_INVOKED_AS"))
                ?: program_invocation_short_name;

        assert(arguments);

        printf("%s>%s %s %s\n",
               ansi_grey(),
               ansi_normal(),
               progname,
               arguments);
}

void help_section(const char *title) {
        assert(title);

        printf("\n%s%s:%s\n",
               ansi_underline(),
               title,
               ansi_normal());
}
