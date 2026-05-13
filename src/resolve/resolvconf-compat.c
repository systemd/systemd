/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "alloc-util.h"
#include "build.h"
#include "extract-word.h"
#include "fileio.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "options.h"
#include "resolvconf-compat.h"
#include "resolvectl.h"
#include "string-util.h"
#include "strv.h"

typedef enum LookupType  {
        LOOKUP_TYPE_REGULAR,
        LOOKUP_TYPE_PRIVATE,
        LOOKUP_TYPE_EXCLUSIVE, /* -x */
} LookupType;

static int resolvconf_help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("resolvconf", &options);
        if (r < 0)
                return r;

        help_cmdline("-a INTERFACE <FILE");
        help_cmdline("-d INTERFACE");
        help_abstract("Register DNS server and domain configuration with systemd-resolved.");

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\n"
               "This is a compatibility alias for the resolvectl(1) tool, providing native\n"
               "command line compatibility with the resolvconf(8) tool of various Linux\n"
               "distributions and BSD systems. Some options supported by other implementations\n"
               "are not supported and are ignored: -m, -u. Various options supported by other\n"
               "implementations are not supported and will cause the invocation to fail:\n"
               "-I, -i, -l, -R, -r, -v, -V, --enable-updates, --disable-updates,\n"
               "--updates-are-enabled.\n");

        help_man_page_reference("resolvectl", "1");
        return 0;
}

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

static int parse_stdin(LookupType lookup_type) {
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

        switch (lookup_type) {
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

        assert(argc >= 0);
        assert(argv);

        /* openresolv checks these environment variables */
        LookupType lookup_type = LOOKUP_TYPE_REGULAR;

        if (getenv("IF_EXCLUSIVE"))
                lookup_type = LOOKUP_TYPE_EXCLUSIVE;
        if (getenv("IF_PRIVATE"))
                lookup_type = LOOKUP_TYPE_PRIVATE;

        arg_mode = _MODE_INVALID;

        OptionParser opts = { argc, argv, .namespace = "resolvconf" };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("resolvconf"): {}

                OPTION_COMMON_HELP:
                        return resolvconf_help();

                OPTION_COMMON_VERSION:
                        return version();

                /* -a and -d is what everybody can agree on */
                OPTION_SHORT('a', NULL, "Register per-interface DNS server and domain data"):
                        arg_mode = MODE_SET_LINK;
                        break;

                OPTION_SHORT('d', NULL, "Unregister per-interface DNS server and domain data"):
                        arg_mode = MODE_REVERT_LINK;
                        break;

                OPTION_SHORT('p', NULL, "Do not use this interface as default route"):
                        lookup_type = LOOKUP_TYPE_PRIVATE;
                        break;

                OPTION_SHORT('f', NULL, "Ignore if specified interface does not exist"):
                        arg_ifindex_permissive = true;
                        break;

                /* The exclusive/private/force stuff is an openresolv invention, we support in some skewed way */
                OPTION_SHORT('x', NULL, "Send DNS traffic preferably over this interface"):
                        lookup_type = LOOKUP_TYPE_EXCLUSIVE;
                        break;

                /* The metrics stuff is an openresolv invention we ignore (and don't really need) */
                OPTION_SHORT('m', "ARG", /* help= */ NULL):
                        log_debug("Switch -%c ignored.", opts.opt->short_code);
                        break;

                /* -u supposedly should "update all subscribers". We have no subscribers, hence let's make
                    this a NOP, and exit immediately, cleanly. */
                OPTION_SHORT('u', NULL, /* help= */ NULL):
                        log_info("Switch -%c ignored.", opts.opt->short_code);
                        return 0;

                /* The following options are openresolv inventions we don't support. */
                OPTION_SHORT('I', NULL,  /* help= */ NULL): {}
                OPTION_SHORT('i', "ARG", /* help= */ NULL): {}
                OPTION_SHORT('l', "ARG", /* help= */ NULL): {}
                OPTION_SHORT('R', NULL,  /* help= */ NULL): {}
                OPTION_SHORT('r', "ARG", /* help= */ NULL): {}
                OPTION_SHORT('v', NULL,  /* help= */ NULL): {}
                OPTION_SHORT('V', NULL,  /* help= */ NULL):
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Switch -%c not supported.", opts.opt->short_code);

                /* The Debian resolvconf commands we don't support. */
                OPTION_LONG("enable-updates", NULL, /* help= */ NULL):
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Switch --enable-updates not supported.");
                OPTION_LONG("disable-updates", NULL, /* help= */ NULL):
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Switch --disable-updates not supported.");
                OPTION_LONG("updates-are-enabled", NULL, /* help= */ NULL):
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Switch --updates-are-enabled not supported.");
                }

        if (arg_mode == _MODE_INVALID)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected either -a or -d on the command line.");

        if (option_parser_get_n_args(&opts) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected interface name as argument.");

        r = ifname_resolvconf_mangle(option_parser_get_arg(&opts, 0));
        if (r <= 0)
                return r;

        if (arg_mode == MODE_SET_LINK) {
                r = parse_stdin(lookup_type);
                if (r < 0)
                        return r;
        }

        return 1; /* work to do */
}
