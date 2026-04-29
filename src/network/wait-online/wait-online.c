/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "build.h"
#include "daemon-util.h"
#include "format-table.h"
#include "hashmap.h"
#include "help-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "socket-util.h"
#include "strv.h"
#include "time-util.h"
#include "wait-online-manager.h"

static bool arg_quiet = false;
static usec_t arg_timeout = 120 * USEC_PER_SEC;
static Hashmap *arg_interfaces = NULL;
static char **arg_ignore = NULL;
static LinkOperationalStateRange arg_required_operstate = LINK_OPERSTATE_RANGE_INVALID;
static AddressFamily arg_required_family = ADDRESS_FAMILY_NO;
static bool arg_any = false;
static bool arg_requires_dns = false;

STATIC_DESTRUCTOR_REGISTER(arg_interfaces, hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(arg_ignore, strv_freep);

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_cmdline("[OPTIONS...]");
        help_abstract("Block until network is configured.");

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-networkd-wait-online.service", "8");
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
                        return log_error_errno(r, "Invalid operational state range: %s", p + 1);

                ifname = strndup(str, p - str);
        } else {
                *range = LINK_OPERSTATE_RANGE_INVALID;
                ifname = strdup(str);
        }
        if (!ifname)
                return log_oom();

        if (!ifname_valid(ifname))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid interface name: %s", ifname);

        r = hashmap_ensure_put(&arg_interfaces, &string_hash_ops_free_free, ifname, range);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to store interface name: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "Interface name %s is already specified.", ifname);

        TAKE_PTR(ifname);
        TAKE_PTR(range);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('q', "quiet", NULL, "Do not show status information"):
                        arg_quiet = true;
                        break;

                OPTION('i', "interface", "IFNAME[:MIN[:MAX]]",
                       "Block until at least these interfaces have appeared, "
                       "in the operational state between MIN and MAX"):
                        r = parse_interface_with_operstate_range(opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("ignore", "IFNAME", "Don't take these interfaces into account"):
                        if (strv_extend(&arg_ignore, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION('o', "operational-state", "MIN[:MAX]",
                       "Require operational state between MIN and MAX"):
                        r = parse_operational_state_range(opts.arg, &arg_required_operstate);
                        if (r < 0)
                                return log_error_errno(r, "Invalid operational state range '%s'", opts.arg);
                        break;

                OPTION('4', "ipv4", NULL, "Require at least one IPv4 address"):
                        arg_required_family |= ADDRESS_FAMILY_IPV4;
                        break;

                OPTION('6', "ipv6", NULL, "Require at least one IPv6 address"):
                        arg_required_family |= ADDRESS_FAMILY_IPV6;
                        break;

                OPTION_LONG("any", NULL, "Wait until at least one of the interfaces is online"):
                        arg_any = true;
                        break;

                OPTION_LONG("timeout", "SECS", "Maximum time to wait for network connectivity"):
                        r = parse_sec(opts.arg, &arg_timeout);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "dns", "BOOL",
                                  "Require at least one DNS server to be accessible"):
                        r = parse_boolean_argument("--dns", opts.arg, &arg_requires_dns);
                        if (r < 0)
                                return r;
                        break;
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

        r = manager_new(&m,
                        arg_interfaces,
                        arg_ignore,
                        arg_required_operstate,
                        arg_required_family,
                        arg_any,
                        arg_timeout,
                        arg_requires_dns);
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
