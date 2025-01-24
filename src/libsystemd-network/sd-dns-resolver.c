/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-resolver-internal.h"
#include "macro.h"
#include "unaligned.h"
#include "socket-netlink.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

void sd_dns_resolver_done(sd_dns_resolver *res) {
        assert(res);

        res->auth_name = mfree(res->auth_name);
        res->addrs = mfree(res->addrs);
        res->dohpath = mfree(res->dohpath);
}

sd_dns_resolver *sd_dns_resolver_unref(sd_dns_resolver *res) {
        if (!res)
                return NULL;

        sd_dns_resolver_done(res);
        return mfree(res);
}

void dns_resolver_done_many(sd_dns_resolver resolvers[], size_t n) {
        assert(resolvers || n == 0);

        FOREACH_ARRAY(res, resolvers, n)
                sd_dns_resolver_done(res);

        free(resolvers);
}

int dns_resolver_prio_compare(const sd_dns_resolver *a, const sd_dns_resolver *b) {
        return CMP(ASSERT_PTR(a)->priority, ASSERT_PTR(b)->priority);
}

int sd_dns_resolver_get_priority(sd_dns_resolver *res, uint16_t *ret_priority) {
        assert_return(res, -EINVAL);
        assert_return(ret_priority, -EINVAL);

        *ret_priority = res->priority;
        return 0;
}

int sd_dns_resolver_get_adn(sd_dns_resolver *res, const char **ret_adn) {
        assert_return(res, -EINVAL);
        assert_return(ret_adn, -EINVAL);

        /* Without adn only Do53 can be supported */
        if (!res->auth_name)
                return -ENODATA;

        *ret_adn = res->auth_name;
        return 0;
}

int sd_dns_resolver_get_inet_addresses(sd_dns_resolver *res, const struct in_addr **ret_addrs, size_t
                *ret_n_addrs) {
        assert_return(res, -EINVAL);
        assert_return(ret_addrs, -EINVAL);
        assert_return(ret_n_addrs, -EINVAL);
        assert_return(res->family == AF_INET, -EINVAL);

        /* ADN-only mode has no addrs */
        if (res->n_addrs == 0)
                return -ENODATA;

        struct in_addr *addrs = new(struct in_addr, res->n_addrs);
        if (!addrs)
                return -ENOMEM;

        for (size_t i = 0; i < res->n_addrs; i++)
                addrs[i] = res->addrs[i].in;
        *ret_addrs = addrs;
        *ret_n_addrs = res->n_addrs;

        return 0;
}

int sd_dns_resolver_get_inet6_addresses(sd_dns_resolver *res, const struct in6_addr **ret_addrs, size_t
                *ret_n_addrs) {
        assert_return(res, -EINVAL);
        assert_return(ret_addrs, -EINVAL);
        assert_return(ret_n_addrs, -EINVAL);
        assert_return(res->family == AF_INET6, -EINVAL);

        /* ADN-only mode has no addrs */
        if (res->n_addrs == 0)
                return -ENODATA;

        struct in6_addr *addrs = new(struct in6_addr, res->n_addrs);
        if (!addrs)
                return -ENOMEM;

        for (size_t i = 0; i < res->n_addrs; i++)
                addrs[i] = res->addrs[i].in6;
        *ret_addrs = addrs;
        *ret_n_addrs = res->n_addrs;

        return 0;
}

int sd_dns_resolver_get_alpn(sd_dns_resolver *res, sd_dns_alpn_flags *ret_alpn) {
        assert_return(res, -EINVAL);
        assert_return(ret_alpn, -EINVAL);

        /* ADN-only mode has no transports */
        if (!res->transports)
                return -ENODATA;

        *ret_alpn = res->transports;
        return 0;
}

int sd_dns_resolver_get_port(sd_dns_resolver *res, uint16_t *ret_port) {
        assert_return(res, -EINVAL);
        assert_return(ret_port, -EINVAL);

        /* port = 0 is the default port */
        *ret_port = res->port;
        return 0;
}

int sd_dns_resolver_get_dohpath(sd_dns_resolver *res, const char **ret_dohpath) {
        assert_return(res, -EINVAL);
        assert_return(ret_dohpath, -EINVAL);

        /* only present in DoH resolvers */
        if (!res->dohpath)
                return -ENODATA;

        *ret_dohpath = res->dohpath;
        return 0;
}

void siphash24_compress_resolver(const sd_dns_resolver *res, struct siphash *state) {
        assert(res);

        siphash24_compress_typesafe(res->priority, state);
        siphash24_compress_typesafe(res->transports, state);
        siphash24_compress_typesafe(res->port, state);

        siphash24_compress_string(res->auth_name, state);
        siphash24_compress_string(res->dohpath, state);

        siphash24_compress_typesafe(res->family, state);
        FOREACH_ARRAY(addr, res->addrs, res->n_addrs)
                siphash24_compress_typesafe(*addr, state);
}

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

const char* format_dns_svc_param_key(uint16_t i, char buf[static DECIMAL_STR_MAX(uint16_t)+3]) {
        assert(buf);

        const char *p = dns_svc_param_key_to_string(i);
        if (p)
                return p;

        return snprintf_ok(buf, DECIMAL_STR_MAX(uint16_t)+3, "key%i", i);
}

int dns_resolver_transports_to_strv(sd_dns_alpn_flags transports, char ***ret) {
        _cleanup_strv_free_ char **ans = NULL;

        assert(ret);

        if (FLAGS_SET(transports, SD_DNS_ALPN_DO53)) {
                /* Do53 has no ALPN, this flag is only for our own usage. */
        }

        if (FLAGS_SET(transports, SD_DNS_ALPN_HTTP_2_TLS))
                if (strv_extend(&ans, "h2") < 0)
                        return -ENOMEM;
        if (FLAGS_SET(transports, SD_DNS_ALPN_HTTP_3))
                if (strv_extend(&ans, "h3") < 0)
                        return -ENOMEM;
        if (FLAGS_SET(transports, SD_DNS_ALPN_DOT))
                if (strv_extend(&ans, "dot") < 0)
                        return -ENOMEM;
        if (FLAGS_SET(transports, SD_DNS_ALPN_DOQ))
                if (strv_extend(&ans, "doq") < 0)
                        return -ENOMEM;

        *ret = TAKE_PTR(ans);
        return 0;
}

int dnr_parse_svc_params(const uint8_t *option, size_t len, sd_dns_resolver *resolver) {
        size_t offset = 0;
        int r;

        assert(option || len == 0);
        assert(resolver);

        sd_dns_alpn_flags transports = 0;
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
                offset += 2;
                if (offset + plen > len)
                        return -EBADMSG;

                switch (key) {
                /* Mandatory keys must be understood by the client, otherwise the record should be discarded.
                 * Automatic mandatory keys must not appear in the mandatory parameter, so these are all
                 * supplementary. We don't understand any supplementary keys, so if the mandatory parameter
                 * is present, we cannot use this record. */
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
                                if (memcmp_nn(&option[poff], alen, "dot", STRLEN("dot")) == 0)
                                        transports |= SD_DNS_ALPN_DOT;
                                if (memcmp_nn(&option[poff], alen, "h2", STRLEN("h2")) == 0)
                                        transports |= SD_DNS_ALPN_HTTP_2_TLS;
                                if (memcmp_nn(&option[poff], alen, "h3", STRLEN("h3")) == 0)
                                        transports |= SD_DNS_ALPN_HTTP_3;
                                if (memcmp_nn(&option[poff], alen, "doq", STRLEN("doq")) == 0)
                                        transports |= SD_DNS_ALPN_DOQ;
                                poff += alen;
                        }
                        if (poff != pend)
                                return -EBADMSG;
                        break;

                case DNS_SVC_PARAM_KEY_PORT:
                        if (plen != sizeof(uint16_t))
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
                        r = make_cstring((const char*) &option[offset], plen,
                                        MAKE_CSTRING_REFUSE_TRAILING_NUL, &dohpath);
                        if (ERRNO_IS_NEG_RESOURCE(r))
                                return r;
                        if (r < 0)
                                return -EBADMSG;
                        /* dohpath is a RFC6750 URI template. We don't parse these, but at least check the
                         * charset is reasonable. */
                        if (!in_charset(dohpath, URI_VALID "{}"))
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

        /* RFC9461 § 5: If the [SvcParam] indicates support for HTTP, "dohpath" MUST be present. */
        if (!dohpath && (FLAGS_SET(transports, SD_DNS_ALPN_HTTP_2_TLS) ||
                        FLAGS_SET(transports, SD_DNS_ALPN_HTTP_3)))
                return -EBADMSG;

        /* No useful transports */
        if (!transports)
                return 0;

        resolver->transports = transports;
        resolver->port = port;
        free_and_replace(resolver->dohpath, dohpath);
        return transports;
}

int dns_resolvers_to_dot_addrs(const sd_dns_resolver *resolvers, size_t n_resolvers,
                struct in_addr_full ***ret_addrs, size_t *ret_n_addrs) {
        assert(ret_addrs);
        assert(ret_n_addrs);
        assert(resolvers || n_resolvers == 0);

        struct in_addr_full **addrs = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(addrs, n, in_addr_full_array_free);

        FOREACH_ARRAY(res, resolvers, n_resolvers) {
                if (!FLAGS_SET(res->transports, SD_DNS_ALPN_DOT))
                        continue;

                FOREACH_ARRAY(i, res->addrs, res->n_addrs) {
                        _cleanup_(in_addr_full_freep) struct in_addr_full *addr = NULL;
                        int r;

                        addr = new0(struct in_addr_full, 1);
                        if (!addr)
                                return -ENOMEM;
                        if (!GREEDY_REALLOC(addrs, n+1))
                                return -ENOMEM;

                        r = free_and_strdup(&addr->server_name, res->auth_name);
                        if (r < 0)
                                return r;
                        addr->family = res->family;
                        addr->port = res->port;
                        addr->address = *i;

                        addrs[n++] = TAKE_PTR(addr);
                }
        }

        *ret_addrs = TAKE_PTR(addrs);
        *ret_n_addrs = n;
        return n;
}

int dns_resolvers_to_dot_strv(const sd_dns_resolver *resolvers, size_t n_resolvers, char ***ret_names) {
        assert(ret_names);
        int r;

        _cleanup_strv_free_ char **names = NULL;
        size_t len = 0;

        struct in_addr_full **addrs = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(addrs, n, in_addr_full_array_free);

        r = dns_resolvers_to_dot_addrs(resolvers, n_resolvers, &addrs, &n);
        if (r < 0)
                return r;

        FOREACH_ARRAY(addr, addrs, n) {
                const char *name = in_addr_full_to_string(*addr);
                if (!name)
                        return -ENOMEM;
                r = strv_extend_with_size(&names, &len, name);
                if (r < 0)
                        return r;
        }

        *ret_names = TAKE_PTR(names);
        return len;
}
