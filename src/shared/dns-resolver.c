/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-resolver.h"
#include "macro-fundamental.h"
#include "string-table.h"
#include "string-util.h"

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
