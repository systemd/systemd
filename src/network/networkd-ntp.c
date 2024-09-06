/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "networkd-network.h"
#include "networkd-ntp.h"
#include "parse-util.h"
#include "strv.h"

/* Let's assume that anything above this number is a user misconfiguration. */
#define MAX_NTP_SERVERS 128U

bool link_get_use_ntp(Link *link, NetworkConfigSource proto) {
        int n, c;

        assert(link);

        if (!link->network)
                return false;

        switch (proto) {
        case NETWORK_CONFIG_SOURCE_DHCP4:
                n = link->network->dhcp_use_ntp;
                c = link->network->compat_dhcp_use_ntp;
                break;
        case NETWORK_CONFIG_SOURCE_DHCP6:
                n = link->network->dhcp6_use_ntp;
                c = link->network->compat_dhcp_use_ntp;
                break;
        default:
                assert_not_reached();
        }

        /* If per-network and per-protocol setting is specified, use it. */
        if (n >= 0)
                return n;

        /* If compat setting is specified, use it. */
        if (c >= 0)
                return c;

        /* Otherwise, defaults to yes. */
        return true;
}

int config_parse_ntp(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***l = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *l = strv_free(*l);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract NTP server name, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = dns_name_is_valid_or_address(w);
                if (r <= 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "%s is not a valid domain name or IP address, ignoring.", w);
                        continue;
                }

                if (strv_length(*l) > MAX_NTP_SERVERS) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "More than %u NTP servers specified, ignoring \"%s\" and any subsequent entries.",
                                   MAX_NTP_SERVERS, w);
                        return 0;
                }

                r = strv_consume(l, TAKE_PTR(w));
                if (r < 0)
                        return log_oom();
        }
}
