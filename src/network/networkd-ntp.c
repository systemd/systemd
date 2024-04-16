/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "networkd-network.h"
#include "networkd-ntp.h"
#include "parse-util.h"
#include "strv.h"

/* Let's assume that anything above this number is a user misconfiguration. */
#define MAX_NTP_SERVERS 128U

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

int config_parse_dhcp_use_ntp(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(IN_SET(ltype, AF_UNSPEC, AF_INET, AF_INET6));
        assert(rvalue);
        assert(data);

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse UseNTP=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        switch (ltype) {
        case AF_INET:
                network->dhcp_use_ntp = r;
                network->dhcp_use_ntp_set = true;
                break;
        case AF_INET6:
                network->dhcp6_use_ntp = r;
                network->dhcp6_use_ntp_set = true;
                break;
        case AF_UNSPEC:
                /* For backward compatibility. */
                if (!network->dhcp_use_ntp_set)
                        network->dhcp_use_ntp = r;
                if (!network->dhcp6_use_ntp_set)
                        network->dhcp6_use_ntp = r;
                break;
        default:
                assert_not_reached();
        }

        return 0;
}
