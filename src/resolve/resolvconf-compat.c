/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <net/if.h>

#include "alloc-util.h"
#include "def.h"
#include "dns-domain.h"
#include "extract-word.h"
#include "fileio.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "resolvconf-compat.h"
#include "resolvectl.h"
#include "resolved-def.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

static int resolvconf_help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("resolvectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s -a INTERFACE < FILE\n"
               "%1$s -d INTERFACE\n"
               "\n"
               "Register DNS server and domain configuration with systemd-resolved.\n\n"
               "  -h --help     Show this help\n"
               "     --version  Show package version\n"
               "  -a            Register per-interface DNS server and domain data\n"
               "  -d            Unregister per-interface DNS server and domain data\n"
               "  -f            Ignore if specified interface does not exist\n"
               "  -x            Send DNS traffic preferably over this interface\n"
               "\n"
               "This is a compatibility alias for the resolvectl(1) tool, providing native\n"
               "command line compatibility with the resolvconf(8) tool of various Linux\n"
               "distributions and BSD systems. Some options supported by other implementations\n"
               "are not supported and are ignored: -m, -p, -u. Various options supported by other\n"
               "implementations are not supported and will cause the invocation to fail:\n"
               "-I, -i, -l, -R, -r, -v, -V, --enable-updates, --disable-updates,\n"
               "--updates-are-enabled.\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link);

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

int resolvconf_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ENABLE_UPDATES,
                ARG_DISABLE_UPDATES,
                ARG_UPDATES_ARE_ENABLED,
        };

        static const struct option options[] = {
                { "help",                no_argument, NULL, 'h'                     },
                { "version",             no_argument, NULL, ARG_VERSION             },

                /* The following are specific to Debian's original resolvconf */
                { "enable-updates",      no_argument, NULL, ARG_ENABLE_UPDATES      },
                { "disable-updates",     no_argument, NULL, ARG_DISABLE_UPDATES     },
                { "updates-are-enabled", no_argument, NULL, ARG_UPDATES_ARE_ENABLED },
                {}
        };

        enum {
                TYPE_REGULAR,
                TYPE_PRIVATE,   /* -p: Not supported, treated identically to TYPE_REGULAR */
                TYPE_EXCLUSIVE, /* -x */
        } type = TYPE_REGULAR;

        int c, r;

        assert(argc >= 0);
        assert(argv);

        /* openresolv checks these environment variables */
        if (getenv("IF_EXCLUSIVE"))
                type = TYPE_EXCLUSIVE;
        if (getenv("IF_PRIVATE"))
                type = TYPE_PRIVATE; /* not actually supported */

        arg_mode = _MODE_INVALID;

        while ((c = getopt_long(argc, argv, "hadxpfm:uIi:l:Rr:vV", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return resolvconf_help();

                case ARG_VERSION:
                        return version();

                /* -a and -d is what everybody can agree on */
                case 'a':
                        arg_mode = MODE_SET_LINK;
                        break;

                case 'd':
                        arg_mode = MODE_REVERT_LINK;
                        break;

                /* The exclusive/private/force stuff is an openresolv invention, we support in some skewed way */
                case 'x':
                        type = TYPE_EXCLUSIVE;
                        break;

                case 'p':
                        type = TYPE_PRIVATE; /* not actually supported */
                        break;

                case 'f':
                        arg_ifindex_permissive = true;
                        break;

                /* The metrics stuff is an openresolv invention we ignore (and don't really need) */
                case 'm':
                        log_debug("Switch -%c ignored.", c);
                        break;

                /* -u supposedly should "update all subscribers". We have no subscribers, hence let's make
                    this a NOP, and exit immediately, cleanly. */
                case 'u':
                        log_info("Switch -%c ignored.", c);
                        return 0;

                /* The following options are openresolv inventions we don't support. */
                case 'I':
                case 'i':
                case 'l':
                case 'R':
                case 'r':
                case 'v':
                case 'V':
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Switch -%c not supported.", c);

                /* The Debian resolvconf commands we don't support. */
                case ARG_ENABLE_UPDATES:
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Switch --enable-updates not supported.");
                case ARG_DISABLE_UPDATES:
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Switch --disable-updates not supported.");
                case ARG_UPDATES_ARE_ENABLED:
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Switch --updates-are-enabled not supported.");

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_mode == _MODE_INVALID)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected either -a or -d on the command line.");

        if (optind+1 != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected interface name as argument.");

        r = ifname_resolvconf_mangle(argv[optind]);
        if (r <= 0)
                return r;

        optind++;

        if (arg_mode == MODE_SET_LINK) {
                unsigned n = 0;

                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        const char *a, *l;

                        r = read_line(stdin, LONG_LINE_MAX, &line);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read from stdin: %m");
                        if (r == 0)
                                break;

                        n++;

                        l = strstrip(line);
                        if (IN_SET(*l, '#', ';', 0))
                                continue;

                        a = first_word(l, "nameserver");
                        if (a) {
                                (void) parse_nameserver(a);
                                continue;
                        }

                        a = first_word(l, "domain");
                        if (!a)
                                a = first_word(l, "search");
                        if (a) {
                                (void) parse_search_domain(a);
                                continue;
                        }

                        log_syntax(NULL, LOG_DEBUG, "stdin", n, 0, "Ignoring resolv.conf line: %s", l);
                }

                if (type == TYPE_EXCLUSIVE) {

                        /* If -x mode is selected, let's preferably route non-suffixed lookups to this interface. This
                         * somewhat matches the original -x behaviour */

                        r = strv_extend(&arg_set_domain, "~.");
                        if (r < 0)
                                return log_oom();

                } else if (type == TYPE_PRIVATE)
                        log_debug("Private DNS server data not supported, ignoring.");

                if (!arg_set_dns)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "No DNS servers specified, refusing operation.");
        }

        return 1; /* work to do */
}
