/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "build.h"
#include "extract-word.h"
#include "fileio.h"
#include "log.h"
#include "pretty-print.h"
#include "resolvconf-compat.h"
#include "resolvectl.h"
#include "string-util.h"
#include "strv.h"

typedef enum LookupType  {
        LOOKUP_TYPE_REGULAR,
        LOOKUP_TYPE_PRIVATE,
        LOOKUP_TYPE_EXCLUSIVE, /* -x */
} LookupType;

LookupType arg_lookup_type = LOOKUP_TYPE_REGULAR;

static int parse_nameserver(const char *string) {
        int r;

        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (strv_push(&arg_set_dns, word) < 0)
                        return log_oom();

                word = NULL;
        }

        return 0;
}

static int parse_search_domain(const char *string) {
        int r;

        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&string, &word, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (strv_push(&arg_set_domain, word) < 0)
                        return log_oom();

                word = NULL;
        }

        return 0;
}

#include "resolvconf-compat.args.inc"

static int help_resolvconf(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("resolvectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s -a INTERFACE <FILE\n"
               "%1$s -d INTERFACE\n"
               "\n"
               "Register DNS server and domain configuration with systemd-resolved.\n\n"
               OPTION_HELP_GENERATED_RESOLVCONF
               "\n"
               "This is a compatibility alias for the resolvectl(1) tool, providing native\n"
               "command line compatibility with the resolvconf(8) tool of various Linux\n"
               "distributions and BSD systems. Some options supported by other implementations\n"
               "are not supported and are ignored: -m, -u. Various options supported by other\n"
               "implementations are not supported and will cause the invocation to fail:\n"
               "-I, -i, -l, -R, -r, -v, -V, --enable-updates, --disable-updates,\n"
               "--updates-are-enabled.\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_stdin(void) {
        int r;

        for (unsigned n = 0;;) {
                _cleanup_free_ char *line = NULL;
                const char *a;

                r = read_stripped_line(stdin, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read from stdin: %m");
                if (r == 0)
                        break;
                n++;

                if (IN_SET(*line, '#', ';', 0))
                        continue;

                a = first_word(line, "nameserver");
                if (a) {
                        (void) parse_nameserver(a);
                        continue;
                }

                a = first_word(line, "domain");
                if (!a)
                        a = first_word(line, "search");
                if (a) {
                        (void) parse_search_domain(a);
                        continue;
                }

                log_syntax(NULL, LOG_DEBUG, "stdin", n, 0, "Ignoring resolv.conf line: %s", line);
        }

        switch (arg_lookup_type) {
        case LOOKUP_TYPE_REGULAR:
                break;

        case LOOKUP_TYPE_PRIVATE:
                arg_disable_default_route = true;
                break;

        case LOOKUP_TYPE_EXCLUSIVE:
                /* If -x mode is selected, let's preferably route non-suffixed lookups to this interface.
                 * This somewhat matches the original -x behaviour */

                r = strv_extend(&arg_set_domain, "~.");
                if (r < 0)
                        return log_oom();
                break;

        default:
                assert_not_reached();
        }

        if (strv_isempty(arg_set_dns))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No DNS servers specified, refusing operation.");

        if (strv_isempty(arg_set_domain)) {
                /* When no domain/search is set, clear the current domains. */
                r = strv_extend(&arg_set_domain, "");
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

int resolvconf_parse_argv(int argc, char *argv[]) {
        int r;

        r = parse_argv_generated_resolvconf(argc, argv);
        if (r <= 0)
                return r;

        if (arg_mode == MODE_SET_LINK) {
                r = parse_stdin();
                if (r < 0)
                        return r;
        }

        return 1; /* work to do */
}
