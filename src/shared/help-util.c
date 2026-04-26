/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ansi-color.h"
#include "help-util.h"
#include "pretty-print.h"

/* These are helpers for putting together --help texts in a uniform way with a common output style. Each
 * function generates a separate part of the --help text:
 *
 *   1. help_cmdline() outputs a brief summary of the command line syntax. This shall be used at least once,
 *      in some cases multiple times. This generally comes first in the output.
 *
 *   2. help_abstract() outputs a brief prose abstract of the command, should carry a single line of text
 *      that gives the user a hint what this tool does. Use only once, right after the last help_cmdline().
 *
 *   3. help_section() can be used to format multiple sections of the --help text. It should be used at least
 *      once for an "Options:" section, but can be used more than once, for programs with many
 *      options/verbs. The first invocation should come right after help_abstract().
 *
 *   4. Finally, help_man_page_reference() adds a final line linking the man page of the tool. This should be
 *      used only once, and terminates the --help text.
 *
 *   Switches and verbs documentation should be inserted after each help_section(). For that ideally use
 *   options.[ch] APIs. */

void help_cmdline(const char *arguments) {
        assert(arguments);

        printf("%s>%s %s %s\n",
               ansi_grey(),
               ansi_normal(),
               program_invocation_short_name,
               arguments);
}

void help_abstract(const char *text) {
        assert(text);

        printf("\n%s%s%s%s\n",
               ansi_highlight(),
               ansi_add_italics(),
               text,
               ansi_normal());
}

void help_section(const char *title) {
        assert(title);

        printf("\n%s%s%s\n",
               ansi_underline(),
               title,
               ansi_normal());
}

void help_man_page_reference(const char *page, const char *section) {
        assert(page);
        assert(section);

        /* Displaying --help texts generally should not fail, hence let's fall back to a simple string in
         * case of OOM. */
        _cleanup_free_ char *link = NULL;
        if (terminal_urlify_man(page, section, &link) < 0)
                printf("\nSee the %s(%s) man page for details.\n", page, section);
        else
                printf("\nSee the %s for details.\n", link);
}
