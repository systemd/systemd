/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-resolver.h"
#include "macro-fundamental.h"
#include "socket-netlink.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

/*
const char *dns_alpn_flag_to_string(DNSALPNFlags alpn) {
        switch (alpn) {
        case SD_DNS_ALPN_HTTP_2_TLS:
                return "h2";
        case SD_DNS_ALPN_HTTP_3:
                return "h3";
        case SD_DNS_ALPN_DOT:
                return "dot";
        case SD_DNS_ALPN_DOQ:
                return "doq";
        default:
                return NULL;
        }
}

DNSALPNFlags dns_alpn_flag_from_string(const char *s) {
        if (streq(s, "h2"))
                return SD_DNS_ALPN_HTTP_2_TLS;
        else if (streq(s, "h3"))
                return SD_DNS_ALPN_HTTP_3;
        else if (streq(s, "dot"))
                return SD_DNS_ALPN_DOT;
        else if (streq(s, "doq"))
                return SD_DNS_ALPN_DOQ;
        else
                return 0;
}
*/

static const char* const dns_svc_param_key_table[_DNS_SVC_PARAM_KEY_MAX_DEFINED] = {
        [DNS_SVC_PARAM_KEY_MANDATORY]       = "mandatory",
        [DNS_SVC_PARAM_KEY_ALPN]            = "alpn",
        [DNS_SVC_PARAM_KEY_NO_DEFAULT_ALPN] = "no-default-alpn",
        [DNS_SVC_PARAM_KEY_PORT]            = "port",
        [DNS_SVC_PARAM_KEY_IPV4HINT]        = "ipv4hint",
        [DNS_SVC_PARAM_KEY_ECH]             = "ech",
        [DNS_SVC_PARAM_KEY_IPV6HINT]        = "ipv6hint",
        [DNS_SVC_PARAM_KEY_DOHPATH]         = "dohpath",
        [DNS_SVC_PARAM_KEY_OHTTP]           = "ohttp",
};
DEFINE_STRING_TABLE_LOOKUP_TO_STRING(dns_svc_param_key, int);

const char *format_dns_svc_param_key(uint16_t i, char buf[static DECIMAL_STR_MAX(uint16_t)+3]) {
        const char *p = dns_svc_param_key_to_string(i);
        if (p)
                return p;

        return snprintf_ok(buf, DECIMAL_STR_MAX(uint16_t)+3, "key%i", i);
}

//FIXME: resolved only supports dot anyway atm
int dns_resolvers_to_dot_addrs(const ResolverData *resolvers, struct in_addr_full ***ret_addrs, size_t *ret_n_addrs) {
        assert(ret_addrs);
        assert(ret_n_addrs);

        struct in_addr_full **addrs = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(addrs, n, in_addr_full_array_free);

        LIST_FOREACH(resolvers, res, resolvers) {
                if (!FLAGS_SET(res->transports, SD_DNS_ALPN_DOT))
                        continue;

                FOREACH_ARRAY(i, res->addrs, res->n_addrs) {
                        _cleanup_(in_addr_full_freep) struct in_addr_full *addr = NULL;
                        int r;

                        addr = new0(struct in_addr_full, 1);
                        if (!addr)
                                return -ENOMEM;
                        if (!GREEDY_REALLOC(addrs, n+1)) {
                                return -ENOMEM;
                        }

                        r = free_and_strdup(&addr->server_name, res->auth_name);
                        if (r < 0)
                                return r;
                        addr->family = AF_INET; //FIXME: only supports ipv4
                        addr->port = res->port;
                        addr->address = (union in_addr_union) *i;

                        addrs[n++] = TAKE_PTR(addr);
                }
        }

        *ret_addrs = TAKE_PTR(addrs);
        *ret_n_addrs = n;
        return n;
}

int dns_resolvers_to_dot_strv(const ResolverData *resolvers, char ***ret_names) {
        assert(ret_names);
        int r;

        _cleanup_strv_free_ char **names = NULL;
        size_t len = 0;

        struct in_addr_full **addrs = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(addrs, n, in_addr_full_array_free);

        r = dns_resolvers_to_dot_addrs(resolvers, &addrs, &n);
        if (r < 0)
                return r;

        FOREACH_ARRAY(addr, addrs, n) {
                const char *name = in_addr_full_to_string(*addr);
                r = strv_extend_with_size(&names, &len, name);
                if (r < 0)
                        return r;

        }

        *ret_names = TAKE_PTR(names);
        return len;
}
