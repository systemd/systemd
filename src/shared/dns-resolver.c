/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-resolver.h"
#include "macro-fundamental.h"
#include "unaligned.h"
#include "socket-netlink.h"
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

int dnr_parse_svc_params(const uint8_t *option, size_t len, ResolverData *resolver) {
        size_t offset = 0;

        assert(resolver);

        DNSALPNFlags transports = 0;
        uint16_t port = 0;
        _cleanup_free_ char *dohpath = NULL;
        bool alpn = false;

        uint16_t lastkey = 0;
        while (offset < len) {
                if (offset + 4 > len)
                        return -EBADMSG;

                uint16_t key = unaligned_read_be16(&option[offset]);
                offset += 2;

                /* RFC9460 § 2.2 SvcParam MUST appear in strictly increasing numeric order */
                if (lastkey >= key)
                        return -EBADMSG;
                lastkey = key;

                uint16_t plen = unaligned_read_be16(&option[offset]);
                if (offset + plen > len)
                        return -EBADMSG;
                offset += 2;

                switch (key) {
                /* Mandatory keys must be understood by the client, otherwise the record should be discarded.
                 * Automatic mandatory keys must not appear in the mandatory parameter, so these are all
                 * supplementary. We don't understand any supplementary keys, so if the mandatory parameter
                 * is present, we cannot use this record.*/
                case DNS_SVC_PARAM_KEY_MANDATORY:
                        if (plen > 0)
                                return -EBADMSG;
                        break;

                case DNS_SVC_PARAM_KEY_ALPN:
                        if (plen == 0)
                                return 0;
                        alpn = true; /* alpn is required. Record that the requirement is met. */

                        size_t poff = offset;
                        size_t pend = offset + plen;
                        while (poff < pend) {
                                uint8_t alen = option[poff++];
                                if (poff + alen > len)
                                        return -EBADMSG;
                                if (alen == 3 && strneq((const char*) &option[poff], "dot", alen))
                                        SET_FLAG(transports, SD_DNS_ALPN_DOT, true);
                                if (alen == 2 && strneq((const char*) &option[poff], "h2", alen))
                                        SET_FLAG(transports, SD_DNS_ALPN_HTTP_2_TLS, true);
                                if (alen == 2 && strneq((const char*) &option[poff], "h3", alen))
                                        SET_FLAG(transports, SD_DNS_ALPN_HTTP_3, true);
                                if (alen == 3 && strneq((const char*) &option[poff], "doq", alen))
                                        SET_FLAG(transports, SD_DNS_ALPN_DOQ, true);
                                poff += alen;
                        }
                        if (poff != pend)
                                return -EBADMSG;
                        break;

                case DNS_SVC_PARAM_KEY_PORT:
                        if (plen != 2)
                                return -EBADMSG;
                        port = unaligned_read_be16(&option[offset]);
                        /* Server should indicate default port by omitting this param */
                        if (port == 0)
                                return -EBADMSG;
                        break;

                /* RFC9463 § 5.1 service params MUST NOT include ipv4hint/ipv6hint */
                case DNS_SVC_PARAM_KEY_IPV4HINT:
                case DNS_SVC_PARAM_KEY_IPV6HINT:
                        return -EBADMSG;

                case DNS_SVC_PARAM_KEY_DOHPATH:
                        if (!make_cstring((const char*) &option[offset], plen,
                                        MAKE_CSTRING_REFUSE_TRAILING_NUL, &dohpath))
                                return -EBADMSG;
                        break;

                default:
                        break;
                }
                offset += plen;
        }
        if (offset != len)
                return -EBADMSG;

        /* DNR cannot be used without alpn */
        if (!alpn)
                return -EBADMSG;

        /* DoH cannot be used without dohpath */
        if (!dohpath)
                SET_FLAG(transports, SD_DNS_ALPN_HTTP_2_TLS|SD_DNS_ALPN_HTTP_3, false);

        /* No useful transports */
        if (!transports)
                return 0;

        resolver->transports = transports;
        resolver->port = port;
        free_and_replace(resolver->dohpath, dohpath);
        return transports;
}
