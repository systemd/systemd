/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <netinet/in.h>

#include "sd-dhcp6-client.h"

#include "alloc-util.h"
#include "dhcp-identifier.h"
#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dhcp6-protocol.h"
#include "dns-domain.h"
#include "memory-util.h"
#include "sparse-endian.h"
#include "strv.h"
#include "unaligned.h"

typedef struct DHCP6StatusOption {
        struct DHCP6Option option;
        be16_t status;
        char msg[];
} _packed_ DHCP6StatusOption;

typedef struct DHCP6AddressOption {
        struct DHCP6Option option;
        struct iaaddr iaaddr;
        uint8_t options[];
} _packed_ DHCP6AddressOption;

typedef struct DHCP6PDPrefixOption {
        struct DHCP6Option option;
        struct iapdprefix iapdprefix;
        uint8_t options[];
} _packed_ DHCP6PDPrefixOption;

#define DHCP6_OPTION_IA_NA_LEN (sizeof(struct ia_na))
#define DHCP6_OPTION_IA_PD_LEN (sizeof(struct ia_pd))
#define DHCP6_OPTION_IA_TA_LEN (sizeof(struct ia_ta))

static int option_append_hdr(uint8_t **buf, size_t *buflen, uint16_t optcode, size_t optlen) {
        DHCP6Option *option;

        assert_return(buf, -EINVAL);
        assert_return(*buf, -EINVAL);
        assert_return(buflen, -EINVAL);

        option = (DHCP6Option*) *buf;

        if (optlen > 0xffff || *buflen < optlen + offsetof(DHCP6Option, data))
                return -ENOBUFS;

        option->code = htobe16(optcode);
        option->len = htobe16(optlen);

        *buf += offsetof(DHCP6Option, data);
        *buflen -= offsetof(DHCP6Option, data);

        return 0;
}

int dhcp6_option_append(uint8_t **buf, size_t *buflen, uint16_t code,
                        size_t optlen, const void *optval) {
        int r;

        assert_return(optval || optlen == 0, -EINVAL);

        r = option_append_hdr(buf, buflen, code, optlen);
        if (r < 0)
                return r;

        memcpy_safe(*buf, optval, optlen);

        *buf += optlen;
        *buflen -= optlen;

        return 0;
}

int dhcp6_option_append_vendor_option(uint8_t **buf, size_t *buflen, OrderedHashmap *vendor_options) {
        sd_dhcp6_option *options;
        int r;

        assert(buf);
        assert(*buf);
        assert(buflen);
        assert(vendor_options);

        ORDERED_HASHMAP_FOREACH(options, vendor_options) {
                _cleanup_free_ uint8_t *p = NULL;
                size_t total;

                total = 4 + 2 + 2 + options->length;

                p = malloc(total);
                if (!p)
                        return -ENOMEM;

                unaligned_write_be32(p, options->enterprise_identifier);
                unaligned_write_be16(p + 4, options->option);
                unaligned_write_be16(p + 6, options->length);
                memcpy(p + 8, options->data, options->length);

                r = dhcp6_option_append(buf, buflen, SD_DHCP6_OPTION_VENDOR_OPTS, total, p);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dhcp6_option_append_ia(uint8_t **buf, size_t *buflen, const DHCP6IA *ia) {
        size_t ia_buflen, ia_addrlen = 0;
        struct ia_na ia_na;
        struct ia_ta ia_ta;
        DHCP6Address *addr;
        uint8_t *ia_hdr;
        uint16_t len;
        void *p;
        int r;

        assert_return(buf, -EINVAL);
        assert_return(*buf, -EINVAL);
        assert_return(buflen, -EINVAL);
        assert_return(ia, -EINVAL);

        /* client should not send set T1 and T2. See, RFC 8415, and issue #18090. */

        switch (ia->type) {
        case SD_DHCP6_OPTION_IA_NA:
                len = DHCP6_OPTION_IA_NA_LEN;
                ia_na = (struct ia_na) {
                        .id = ia->ia_na.id,
                };
                p = &ia_na;
                break;

        case SD_DHCP6_OPTION_IA_TA:
                len = DHCP6_OPTION_IA_TA_LEN;
                ia_ta = (struct ia_ta) {
                        .id = ia->ia_ta.id,
                };
                p = &ia_ta;
                break;

        default:
                return -EINVAL;
        }

        if (*buflen < offsetof(DHCP6Option, data) + len)
                return -ENOBUFS;

        ia_hdr = *buf;
        ia_buflen = *buflen;

        *buf += offsetof(DHCP6Option, data);
        *buflen -= offsetof(DHCP6Option, data);

        memcpy(*buf, p, len);

        *buf += len;
        *buflen -= len;

        LIST_FOREACH(addresses, addr, ia->addresses) {
                struct iaaddr a = {
                        .address = addr->iaaddr.address,
                };

                r = option_append_hdr(buf, buflen, SD_DHCP6_OPTION_IAADDR, sizeof(struct iaaddr));
                if (r < 0)
                        return r;

                memcpy(*buf, &a, sizeof(struct iaaddr));

                *buf += sizeof(struct iaaddr);
                *buflen -= sizeof(struct iaaddr);

                ia_addrlen += offsetof(DHCP6Option, data) + sizeof(struct iaaddr);
        }

        return option_append_hdr(&ia_hdr, &ia_buflen, ia->type, len + ia_addrlen);
}

static int option_append_pd_prefix(uint8_t **buf, size_t *buflen, const DHCP6Address *prefix) {
        struct iapdprefix p;
        int r;

        assert(buf);
        assert(*buf);
        assert(buflen);
        assert(prefix);

        if (prefix->iapdprefix.prefixlen == 0)
                return -EINVAL;

        /* Do not append T1 and T2. */

        p = (struct iapdprefix) {
                .prefixlen = prefix->iapdprefix.prefixlen,
                .address = prefix->iapdprefix.address,
        };

        r = option_append_hdr(buf, buflen, SD_DHCP6_OPTION_IA_PD_PREFIX, sizeof(struct iapdprefix));
        if (r < 0)
                return r;

        memcpy(*buf, &p, sizeof(struct iapdprefix));

        *buf += sizeof(struct iapdprefix);
        *buflen -= sizeof(struct iapdprefix);

        return offsetof(DHCP6Option, data) + sizeof(struct iapdprefix);
}

int dhcp6_option_append_pd(uint8_t **buf, size_t *buflen, const DHCP6IA *pd, const DHCP6Address *hint_pd_prefix) {
        struct ia_pd ia_pd;
        size_t len, pd_buflen;
        uint8_t *pd_hdr;
        int r;

        assert_return(buf, -EINVAL);
        assert_return(*buf, -EINVAL);
        assert_return(buflen, -EINVAL);
        assert_return(pd, -EINVAL);
        assert_return(pd->type == SD_DHCP6_OPTION_IA_PD, -EINVAL);

        /* Do not set T1 and T2. */
        ia_pd = (struct ia_pd) {
                .id = pd->ia_pd.id,
        };
        len = sizeof(struct ia_pd);

        if (*buflen < offsetof(DHCP6Option, data) + len)
                return -ENOBUFS;

        pd_hdr = *buf;
        pd_buflen = *buflen;

        /* The header will be written at the end of this function. */
        *buf += offsetof(DHCP6Option, data);
        *buflen -= offsetof(DHCP6Option, data);

        memcpy(*buf, &ia_pd, len);

        *buf += sizeof(struct ia_pd);
        *buflen -= sizeof(struct ia_pd);

        DHCP6Address *prefix;
        LIST_FOREACH(addresses, prefix, pd->addresses) {
                r = option_append_pd_prefix(buf, buflen, prefix);
                if (r < 0)
                        return r;

                len += r;
        }

        if (hint_pd_prefix && hint_pd_prefix->iapdprefix.prefixlen > 0) {
                r = option_append_pd_prefix(buf, buflen, hint_pd_prefix);
                if (r < 0)
                        return r;

                len += r;
        }

        return option_append_hdr(&pd_hdr, &pd_buflen, pd->type, len);
}

int dhcp6_option_append_fqdn(uint8_t **buf, size_t *buflen, const char *fqdn) {
        uint8_t buffer[1 + DNS_WIRE_FORMAT_HOSTNAME_MAX];
        int r;

        assert_return(buf && *buf && buflen && fqdn, -EINVAL);

        buffer[0] = DHCP6_FQDN_FLAG_S; /* Request server to perform AAAA RR DNS updates */

        /* Store domain name after flags field */
        r = dns_name_to_wire_format(fqdn, buffer + 1, sizeof(buffer) - 1,  false);
        if (r <= 0)
                return r;

        /*
         * According to RFC 4704, chapter 4.2 only add terminating zero-length
         * label in case a FQDN is provided. Since dns_name_to_wire_format
         * always adds terminating zero-length label remove if only a hostname
         * is provided.
         */
        if (dns_name_is_single_label(fqdn))
                r--;

        r = dhcp6_option_append(buf, buflen, SD_DHCP6_OPTION_FQDN, 1 + r, buffer);

        return r;
}

int dhcp6_option_append_user_class(uint8_t **buf, size_t *buflen, char * const *user_class) {
        _cleanup_free_ uint8_t *p = NULL;
        size_t total = 0, offset = 0;
        char * const *s;

        assert(buf);
        assert(*buf);
        assert(buflen);
        assert(!strv_isempty(user_class));

        STRV_FOREACH(s, user_class) {
                size_t len = strlen(*s);
                uint8_t *q;

                if (len > 0xffff || len == 0)
                        return -EINVAL;
                q = realloc(p, total + len + 2);
                if (!q)
                        return -ENOMEM;

                p = q;

                unaligned_write_be16(&p[offset], len);
                memcpy(&p[offset + 2], *s, len);

                offset += 2 + len;
                total += 2 + len;
        }

        return dhcp6_option_append(buf, buflen, SD_DHCP6_OPTION_USER_CLASS, total, p);
}

int dhcp6_option_append_vendor_class(uint8_t **buf, size_t *buflen, char * const *vendor_class) {
        _cleanup_free_ uint8_t *p = NULL;
        uint32_t enterprise_identifier;
        size_t total, offset;
        char * const *s;

        assert(buf);
        assert(*buf);
        assert(buflen);
        assert(!strv_isempty(vendor_class));

        enterprise_identifier = htobe32(SYSTEMD_PEN);

        p = memdup(&enterprise_identifier, sizeof(enterprise_identifier));
        if (!p)
                return -ENOMEM;

        total = sizeof(enterprise_identifier);
        offset = total;

        STRV_FOREACH(s, vendor_class) {
                size_t len = strlen(*s);
                uint8_t *q;

                if (len > UINT16_MAX || len == 0)
                        return -EINVAL;

                q = realloc(p, total + len + 2);
                if (!q)
                        return -ENOMEM;

                p = q;

                unaligned_write_be16(&p[offset], len);
                memcpy(&p[offset + 2], *s, len);

                offset += 2 + len;
                total += 2 + len;
        }

        return dhcp6_option_append(buf, buflen, SD_DHCP6_OPTION_VENDOR_CLASS, total, p);
}

static int option_parse_hdr(uint8_t **buf, size_t *buflen, uint16_t *optcode, size_t *optlen) {
        DHCP6Option *option = (DHCP6Option*) *buf;
        uint16_t len;

        assert_return(buf, -EINVAL);
        assert_return(optcode, -EINVAL);
        assert_return(optlen, -EINVAL);

        if (*buflen < offsetof(DHCP6Option, data))
                return -ENOMSG;

        len = be16toh(option->len);

        if (len > *buflen)
                return -ENOMSG;

        *optcode = be16toh(option->code);
        *optlen = len;

        *buf += 4;
        *buflen -= 4;

        return 0;
}

int dhcp6_option_parse(uint8_t **buf, size_t *buflen, uint16_t *optcode,
                       size_t *optlen, uint8_t **optvalue) {
        int r;

        assert_return(buf && buflen && optcode && optlen && optvalue, -EINVAL);

        r = option_parse_hdr(buf, buflen, optcode, optlen);
        if (r < 0)
                return r;

        if (*optlen > *buflen)
                return -ENOBUFS;

        *optvalue = *buf;
        *buflen -= *optlen;
        *buf += *optlen;

        return 0;
}

int dhcp6_option_parse_status(DHCP6Option *option, size_t len) {
        DHCP6StatusOption *statusopt = (DHCP6StatusOption *)option;

        if (len < sizeof(DHCP6StatusOption) ||
            be16toh(option->len) + offsetof(DHCP6Option, data) < sizeof(DHCP6StatusOption))
                return -ENOBUFS;

        return be16toh(statusopt->status);
}

static int dhcp6_option_parse_address(DHCP6Option *option, DHCP6IA *ia, uint32_t *ret_lifetime_valid) {
        DHCP6AddressOption *addr_option = (DHCP6AddressOption *)option;
        DHCP6Address *addr;
        uint32_t lt_valid, lt_pref;
        int r;

        if (be16toh(option->len) + offsetof(DHCP6Option, data) < sizeof(*addr_option))
                return -ENOBUFS;

        lt_valid = be32toh(addr_option->iaaddr.lifetime_valid);
        lt_pref = be32toh(addr_option->iaaddr.lifetime_preferred);

        if (lt_valid == 0 || lt_pref > lt_valid) {
                log_dhcp6_client(client,
                                 "Valid lifetime of an IA address is zero or "
                                 "preferred lifetime %"PRIu32" > valid lifetime %"PRIu32,
                                 lt_pref, lt_valid);
                return -EINVAL;
        }

        if (be16toh(option->len) + offsetof(DHCP6Option, data) > sizeof(*addr_option)) {
                r = dhcp6_option_parse_status((DHCP6Option *)addr_option->options, be16toh(option->len) + offsetof(DHCP6Option, data) - sizeof(*addr_option));
                if (r < 0)
                        return r;
                if (r > 0) {
                        log_dhcp6_client(client, "Non-zero status code '%s' for address is received",
                                         dhcp6_message_status_to_string(r));
                        return -EINVAL;
                }
        }

        addr = new0(DHCP6Address, 1);
        if (!addr)
                return -ENOMEM;

        LIST_INIT(addresses, addr);
        memcpy(&addr->iaaddr, option->data, sizeof(addr->iaaddr));

        LIST_PREPEND(addresses, ia->addresses, addr);

        *ret_lifetime_valid = be32toh(addr->iaaddr.lifetime_valid);

        return 0;
}

static int dhcp6_option_parse_pdprefix(DHCP6Option *option, DHCP6IA *ia, uint32_t *ret_lifetime_valid) {
        DHCP6PDPrefixOption *pdprefix_option = (DHCP6PDPrefixOption *)option;
        DHCP6Address *prefix;
        uint32_t lt_valid, lt_pref;
        int r;

        if (be16toh(option->len) + offsetof(DHCP6Option, data) < sizeof(*pdprefix_option))
                return -ENOBUFS;

        lt_valid = be32toh(pdprefix_option->iapdprefix.lifetime_valid);
        lt_pref = be32toh(pdprefix_option->iapdprefix.lifetime_preferred);

        if (lt_valid == 0 || lt_pref > lt_valid) {
                log_dhcp6_client(client,
                                 "Valid lifetieme of a PD prefix is zero or "
                                 "preferred lifetime %"PRIu32" > valid lifetime %"PRIu32,
                                 lt_pref, lt_valid);
                return -EINVAL;
        }

        if (be16toh(option->len) + offsetof(DHCP6Option, data) > sizeof(*pdprefix_option)) {
                r = dhcp6_option_parse_status((DHCP6Option *)pdprefix_option->options, be16toh(option->len) + offsetof(DHCP6Option, data) - sizeof(*pdprefix_option));
                if (r < 0)
                        return r;
                if (r > 0) {
                        log_dhcp6_client(client, "Non-zero status code '%s' for PD prefix is received",
                                         dhcp6_message_status_to_string(r));
                        return -EINVAL;
                }
        }

        prefix = new0(DHCP6Address, 1);
        if (!prefix)
                return -ENOMEM;

        LIST_INIT(addresses, prefix);
        memcpy(&prefix->iapdprefix, option->data, sizeof(prefix->iapdprefix));

        LIST_PREPEND(addresses, ia->addresses, prefix);

        *ret_lifetime_valid = be32toh(prefix->iapdprefix.lifetime_valid);

        return 0;
}

int dhcp6_option_parse_ia(DHCP6Option *iaoption, DHCP6IA *ia, uint16_t *ret_status_code) {
        uint32_t lt_t1, lt_t2, lt_valid = 0, lt_min = UINT32_MAX;
        uint16_t iatype, optlen;
        size_t iaaddr_offset;
        int r = 0, status;
        size_t i, len;
        uint16_t opt;

        assert_return(ia, -EINVAL);
        assert_return(!ia->addresses, -EINVAL);

        iatype = be16toh(iaoption->code);
        len = be16toh(iaoption->len);

        switch (iatype) {
        case SD_DHCP6_OPTION_IA_NA:

                if (len < DHCP6_OPTION_IA_NA_LEN)
                        return -ENOBUFS;

                iaaddr_offset = DHCP6_OPTION_IA_NA_LEN;
                memcpy(&ia->ia_na, iaoption->data, sizeof(ia->ia_na));

                lt_t1 = be32toh(ia->ia_na.lifetime_t1);
                lt_t2 = be32toh(ia->ia_na.lifetime_t2);

                if (lt_t1 && lt_t2 && lt_t1 > lt_t2) {
                        log_dhcp6_client(client, "IA NA T1 %"PRIu32"sec > T2 %"PRIu32"sec", lt_t1, lt_t2);
                        return -EINVAL;
                }

                break;

        case SD_DHCP6_OPTION_IA_PD:

                if (len < sizeof(ia->ia_pd))
                        return -ENOBUFS;

                iaaddr_offset = sizeof(ia->ia_pd);
                memcpy(&ia->ia_pd, iaoption->data, sizeof(ia->ia_pd));

                lt_t1 = be32toh(ia->ia_pd.lifetime_t1);
                lt_t2 = be32toh(ia->ia_pd.lifetime_t2);

                if (lt_t1 && lt_t2 && lt_t1 > lt_t2) {
                        log_dhcp6_client(client, "IA PD T1 %"PRIu32"sec > T2 %"PRIu32"sec", lt_t1, lt_t2);
                        return -EINVAL;
                }

                break;

        case SD_DHCP6_OPTION_IA_TA:
                if (len < DHCP6_OPTION_IA_TA_LEN)
                        return -ENOBUFS;

                iaaddr_offset = DHCP6_OPTION_IA_TA_LEN;
                memcpy(&ia->ia_ta.id, iaoption->data, sizeof(ia->ia_ta));

                break;

        default:
                return -ENOMSG;
        }

        ia->type = iatype;
        i = iaaddr_offset;

        while (i < len) {
                DHCP6Option *option = (DHCP6Option *)&iaoption->data[i];

                if (len < i + sizeof(*option) || len < i + sizeof(*option) + be16toh(option->len))
                        return -ENOBUFS;

                opt = be16toh(option->code);
                optlen = be16toh(option->len);

                switch (opt) {
                case SD_DHCP6_OPTION_IAADDR:

                        if (!IN_SET(ia->type, SD_DHCP6_OPTION_IA_NA, SD_DHCP6_OPTION_IA_TA)) {
                                log_dhcp6_client(client, "IA Address option not in IA NA or TA option");
                                return -EINVAL;
                        }

                        r = dhcp6_option_parse_address(option, ia, &lt_valid);
                        if (r < 0 && r != -EINVAL)
                                return r;
                        if (r >= 0 && lt_valid < lt_min)
                                lt_min = lt_valid;

                        break;

                case SD_DHCP6_OPTION_IA_PD_PREFIX:

                        if (!IN_SET(ia->type, SD_DHCP6_OPTION_IA_PD)) {
                                log_dhcp6_client(client, "IA PD Prefix option not in IA PD option");
                                return -EINVAL;
                        }

                        r = dhcp6_option_parse_pdprefix(option, ia, &lt_valid);
                        if (r < 0 && r != -EINVAL)
                                return r;
                        if (r >= 0 && lt_valid < lt_min)
                                lt_min = lt_valid;

                        break;

                case SD_DHCP6_OPTION_STATUS_CODE:

                        status = dhcp6_option_parse_status(option, optlen + offsetof(DHCP6Option, data));
                        if (status < 0)
                                return status;

                        if (status > 0) {
                                if (ret_status_code)
                                        *ret_status_code = status;

                                log_dhcp6_client(client, "IA status %s",
                                                 dhcp6_message_status_to_string(status));

                                return 0;
                        }

                        break;

                default:
                        log_dhcp6_client(client, "Unknown IA option %d", opt);
                        break;
                }

                i += sizeof(*option) + optlen;
        }

        switch(iatype) {
        case SD_DHCP6_OPTION_IA_NA:
                if (!ia->ia_na.lifetime_t1 && !ia->ia_na.lifetime_t2 && lt_min != UINT32_MAX) {
                        lt_t1 = lt_min / 2;
                        lt_t2 = lt_min / 10 * 8;
                        ia->ia_na.lifetime_t1 = htobe32(lt_t1);
                        ia->ia_na.lifetime_t2 = htobe32(lt_t2);

                        log_dhcp6_client(client, "Computed IA NA T1 %"PRIu32"sec and T2 %"PRIu32"sec as both were zero",
                                         lt_t1, lt_t2);
                }

                break;

        case SD_DHCP6_OPTION_IA_PD:
                if (!ia->ia_pd.lifetime_t1 && !ia->ia_pd.lifetime_t2 && lt_min != UINT32_MAX) {
                        lt_t1 = lt_min / 2;
                        lt_t2 = lt_min / 10 * 8;
                        ia->ia_pd.lifetime_t1 = htobe32(lt_t1);
                        ia->ia_pd.lifetime_t2 = htobe32(lt_t2);

                        log_dhcp6_client(client, "Computed IA PD T1 %"PRIu32"sec and T2 %"PRIu32"sec as both were zero",
                                         lt_t1, lt_t2);
                }

                break;

        default:
                break;
        }

        if (ret_status_code)
                *ret_status_code = 0;

        return 1;
}

int dhcp6_option_parse_ip6addrs(uint8_t *optval, uint16_t optlen,
                                struct in6_addr **addrs, size_t count,
                                size_t *allocated) {

        if (optlen == 0 || optlen % sizeof(struct in6_addr) != 0)
                return -EINVAL;

        if (!GREEDY_REALLOC(*addrs, *allocated,
                            count * sizeof(struct in6_addr) + optlen))
                return -ENOMEM;

        memcpy(*addrs + count, optval, optlen);

        count += optlen / sizeof(struct in6_addr);

        return count;
}

static int parse_domain(const uint8_t **data, uint16_t *len, char **out_domain) {
        _cleanup_free_ char *ret = NULL;
        size_t n = 0, allocated = 0;
        const uint8_t *optval = *data;
        uint16_t optlen = *len;
        bool first = true;
        int r;

        if (optlen <= 1)
                return -ENODATA;

        for (;;) {
                const char *label;
                uint8_t c;

                if (optlen == 0)
                        break;

                c = *optval;
                optval++;
                optlen--;

                if (c == 0)
                        /* End label */
                        break;
                if (c > 63)
                        return -EBADMSG;
                if (c > optlen)
                        return -EMSGSIZE;

                /* Literal label */
                label = (const char *)optval;
                optval += c;
                optlen -= c;

                if (!GREEDY_REALLOC(ret, allocated, n + !first + DNS_LABEL_ESCAPED_MAX))
                        return -ENOMEM;

                if (first)
                        first = false;
                else
                        ret[n++] = '.';

                r = dns_label_escape(label, c, ret + n, DNS_LABEL_ESCAPED_MAX);
                if (r < 0)
                        return r;

                n += r;
        }

        if (n) {
                if (!GREEDY_REALLOC(ret, allocated, n + 1))
                        return -ENOMEM;
                ret[n] = 0;
        }

        *out_domain = TAKE_PTR(ret);
        *data = optval;
        *len = optlen;

        return n;
}

int dhcp6_option_parse_domainname(const uint8_t *optval, uint16_t optlen, char **str) {
        _cleanup_free_ char *domain = NULL;
        int r;

        r = parse_domain(&optval, &optlen, &domain);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENODATA;
        if (optlen != 0)
                return -EINVAL;

        *str = TAKE_PTR(domain);
        return 0;
}

int dhcp6_option_parse_domainname_list(const uint8_t *optval, uint16_t optlen, char ***str_arr) {
        size_t idx = 0;
        _cleanup_strv_free_ char **names = NULL;
        int r;

        if (optlen <= 1)
                return -ENODATA;
        if (optval[optlen - 1] != '\0')
                return -EINVAL;

        while (optlen > 0) {
                _cleanup_free_ char *ret = NULL;

                r = parse_domain(&optval, &optlen, &ret);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = strv_extend(&names, ret);
                if (r < 0)
                        return r;

                idx++;
        }

        *str_arr = TAKE_PTR(names);

        return idx;
}

static sd_dhcp6_option* dhcp6_option_free(sd_dhcp6_option *i) {
        if (!i)
                return NULL;

        free(i->data);
        return mfree(i);
}

int sd_dhcp6_option_new(uint16_t option, const void *data, size_t length, uint32_t enterprise_identifier, sd_dhcp6_option **ret) {
        assert_return(ret, -EINVAL);
        assert_return(length == 0 || data, -EINVAL);

        _cleanup_free_ void *q = memdup(data, length);
        if (!q)
                return -ENOMEM;

        sd_dhcp6_option *p = new(sd_dhcp6_option, 1);
        if (!p)
                return -ENOMEM;

        *p = (sd_dhcp6_option) {
                .n_ref = 1,
                .option = option,
                .enterprise_identifier = enterprise_identifier,
                .length = length,
                .data = TAKE_PTR(q),
        };

        *ret = p;
        return 0;
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_option, sd_dhcp6_option, dhcp6_option_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                dhcp6_option_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                sd_dhcp6_option,
                sd_dhcp6_option_unref);
