/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sd-daemon.h"

#include "daemon-util.h"
#include "main-func.h"
#include "manager.h"
#include "pretty-print.h"
#include "signal-util.h"
#include "socket-util.h"
#include "strv.h"

static bool arg_quiet = false;
static usec_t arg_timeout = 120 * USEC_PER_SEC;
static Hashmap *arg_interfaces = NULL;
static char **arg_ignore = NULL;
static LinkOperationalStateRange arg_required_operstate = { _LINK_OPERSTATE_INVALID, _LINK_OPERSTATE_INVALID };
static AddressFamily arg_required_family = ADDRESS_FAMILY_NO;
static bool arg_any = false;

STATIC_DESTRUCTOR_REGISTER(arg_interfaces, hashmap_free_free_freep);
STATIC_DESTRUCTOR_REGISTER(arg_ignore, strv_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-networkd-wait-online.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Block until network is configured.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Print version string\n"
               "  -q --quiet                Do not show status information\n"
               "  -i --interface=INTERFACE[:MIN_OPERSTATE[:MAX_OPERSTATE]]\n"
               "                            Block until at least these interfaces have appeared\n"
               "     --ignore=INTERFACE     Don't take these interfaces into account\n"
               "  -o --operational-state=MIN_OPERSTATE[:MAX_OPERSTATE]\n"
               "                            Required operational state\n"
               "  -4 --ipv4                 Requires at least one IPv4 address\n"
               "  -6 --ipv6                 Requires at least one IPv6 address\n"
               "     --any                  Wait until at least one of the interfaces is online\n"
               "     --timeout=SECS         Maximum time to wait for network connectivity\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_interface_with_operstate_range(const char *str) {
        _cleanup_free_ char *ifname = NULL;
        _cleanup_free_ LinkOperationalStateRange *range = NULL;
        const char *p;
        int r;

        assert(str);

        range = new(LinkOperationalStateRange, 1);
        if (!range)
                return log_oom();

        p = strchr(str, ':');
        if (p) {
                r = parse_operational_state_range(p + 1, range);
                if (r < 0)
                         log_error_errno(r, "Invalid operational state range '%s'", p + 1);

                ifname = strndup(optarg, p - optarg);
        } else {
                range->min = _LINK_OPERSTATE_INVALID;
                range->max = _LINK_OPERSTATE_INVALID;
                ifname = strdup(str);
        }
        if (!ifname)
                return log_oom();

        if (!ifname_valid(ifname))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid interface name '%s'", ifname);

        r = hashmap_ensure_put(&arg_interfaces, &string_hash_ops, ifname, TAKE_PTR(range));
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to store interface name: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Interface name %s is already specified", ifname);

        TAKE_PTR(ifname);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_IGNORE,
                ARG_ANY,
                ARG_TIMEOUT,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'         },
                { "version",           no_argument,       NULL, ARG_VERSION },
                { "quiet",             no_argument,       NULL, 'q'         },
                { "interface",         required_argument, NULL, 'i'         },
                { "ignore",            required_argument, NULL, ARG_IGNORE  },
                { "operational-state", required_argument, NULL, 'o'         },
                { "ipv4",              no_argument,       NULL, '4'         },
                { "ipv6",              no_argument,       NULL, '6'         },
                { "any",               no_argument,       NULL, ARG_ANY     },
                { "timeout",           required_argument, NULL, ARG_TIMEOUT },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hi:qo:46", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_VERSION:
                        return version();

                case 'i':
                        r = parse_interface_with_operstate_range(optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IGNORE:
                        if (strv_extend(&arg_ignore, optarg) < 0)
                                return log_oom();

                        break;

                case 'o': {
                        LinkOperationalStateRange range;

                        r = parse_operational_state_range(optarg, &range);
                        if (r < 0)
                                return log_error_errno(r, "Invalid operational state range '%s'", optarg);

                        arg_required_operstate = range;

                        break;
                }

                case '4':
                        arg_required_family |= ADDRESS_FAMILY_IPV4;
                        break;

                case '6':
                        arg_required_family |= ADDRESS_FAMILY_IPV6;
                        break;

                case ARG_ANY:
                        arg_any = true;
                        break;

                case ARG_TIMEOUT:
                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message = NULL;
        int r;

        log_setup();

        umask(0022);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_quiet)
                log_set_max_level(LOG_ERR);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m, arg_interfaces, arg_ignore, arg_required_operstate, arg_required_family, arg_any, arg_timeout);
        if (r < 0)
                return log_error_errno(r, "Could not create manager: %m");

        if (manager_configured(m))
                goto success;

        notify_message = notify_start("READY=1\n"
                                      "STATUS=Waiting for network connections...",
                                      "STATUS=Failed to wait for network connectivity...");

        r = sd_event_loop(m->event);
        if (r == -ETIMEDOUT)
                return log_error_errno(r, "Timeout occurred while waiting for network connectivity.");
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

success:
        notify_message = "STATUS=All interfaces configured...";

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
