/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <netinet/in.h>
#include <string.h>

#include "sd-dhcp6-client.h"

#include "alloc-util.h"
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

static int option_append_hdr(uint8_t **buf, size_t *buflen, uint16_t optcode,
                             size_t optlen) {
        DHCP6Option *option = (DHCP6Option*) *buf;

        assert_return(buf, -EINVAL);
        assert_return(*buf, -EINVAL);
        assert_return(buflen, -EINVAL);

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

int dhcp6_option_append_ia(uint8_t **buf, size_t *buflen, const DHCP6IA *ia) {
        uint16_t len;
        uint8_t *ia_hdr;
        size_t iaid_offset, ia_buflen, ia_addrlen = 0;
        DHCP6Address *addr;
        int r;

        assert_return(buf, -EINVAL);
        assert_return(*buf, -EINVAL);
        assert_return(buflen, -EINVAL);
        assert_return(ia, -EINVAL);

        switch (ia->type) {
        case SD_DHCP6_OPTION_IA_NA:
                len = DHCP6_OPTION_IA_NA_LEN;
                iaid_offset = offsetof(DHCP6IA, ia_na);
                break;

        case SD_DHCP6_OPTION_IA_TA:
                len = DHCP6_OPTION_IA_TA_LEN;
                iaid_offset = offsetof(DHCP6IA, ia_ta);
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

        memcpy(*buf, (char*) ia + iaid_offset, len);

        *buf += len;
        *buflen -= len;

        LIST_FOREACH(addresses, addr, ia->addresses) {
                r = option_append_hdr(buf, buflen, SD_DHCP6_OPTION_IAADDR,
                                      sizeof(addr->iaaddr));
                if (r < 0)
                        return r;

                memcpy(*buf, &addr->iaaddr, sizeof(addr->iaaddr));

                *buf += sizeof(addr->iaaddr);
                *buflen -= sizeof(addr->iaaddr);

                ia_addrlen += offsetof(DHCP6Option, data) + sizeof(addr->iaaddr);
        }

        r = option_append_hdr(&ia_hdr, &ia_buflen, ia->type, len + ia_addrlen);
        if (r < 0)
                return r;

        return 0;
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

int dhcp6_option_append_pd(uint8_t *buf, size_t len, const DHCP6IA *pd) {
        DHCP6Option *option = (DHCP6Option *)buf;
        size_t i = sizeof(*option) + sizeof(pd->ia_pd);
        DHCP6Address *prefix;

        assert_return(buf, -EINVAL);
        assert_return(pd, -EINVAL);
        assert_return(pd->type == SD_DHCP6_OPTION_IA_PD, -EINVAL);

        if (len < i)
                return -ENOBUFS;

        option->code = htobe16(SD_DHCP6_OPTION_IA_PD);

        memcpy(&option->data, &pd->ia_pd, sizeof(pd->ia_pd));

        LIST_FOREACH(addresses, prefix, pd->addresses) {
                DHCP6PDPrefixOption *prefix_opt;

                if (len < i + sizeof(*prefix_opt))
                        return -ENOBUFS;

                prefix_opt = (DHCP6PDPrefixOption *)&buf[i];
                prefix_opt->option.code = htobe16(SD_DHCP6_OPTION_IA_PD_PREFIX);
                prefix_opt->option.len = htobe16(sizeof(prefix_opt->iapdprefix));

                memcpy(&prefix_opt->iapdprefix, &prefix->iapdprefix,
                       sizeof(struct iapdprefix));

                i += sizeof(*prefix_opt);
        }

        option->len = htobe16(i - sizeof(*option));

        return i;
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

static int dhcp6_option_parse_address(DHCP6Option *option, DHCP6IA *ia,
                                      uint32_t *lifetime_valid) {
        DHCP6AddressOption *addr_option = (DHCP6AddressOption *)option;
        DHCP6Address *addr;
        uint32_t lt_valid, lt_pref;
        int r;

        if (be16toh(option->len) + offsetof(DHCP6Option, data) < sizeof(*addr_option))
                return -ENOBUFS;

        lt_valid = be32toh(addr_option->iaaddr.lifetime_valid);
        lt_pref = be32toh(addr_option->iaaddr.lifetime_preferred);

        if (lt_valid == 0 || lt_pref > lt_valid) {
                log_dhcp6_client(client, "Valid lifetime of an IA address is zero or preferred lifetime %d > valid lifetime %d",
                                 lt_pref, lt_valid);

                return 0;
        }

        if (be16toh(option->len) + offsetof(DHCP6Option, data) > sizeof(*addr_option)) {
                r = dhcp6_option_parse_status((DHCP6Option *)addr_option->options, be16toh(option->len) + offsetof(DHCP6Option, data) - sizeof(*addr_option));
                if (r != 0)
                        return r < 0 ? r: 0;
        }

        addr = new0(DHCP6Address, 1);
        if (!addr)
                return -ENOMEM;

        LIST_INIT(addresses, addr);
        memcpy(&addr->iaaddr, option->data, sizeof(addr->iaaddr));

        LIST_PREPEND(addresses, ia->addresses, addr);

        *lifetime_valid = be32toh(addr->iaaddr.lifetime_valid);

        return 0;
}

static int dhcp6_option_parse_pdprefix(DHCP6Option *option, DHCP6IA *ia,
                                       uint32_t *lifetime_valid) {
        DHCP6PDPrefixOption *pdprefix_option = (DHCP6PDPrefixOption *)option;
        DHCP6Address *prefix;
        uint32_t lt_valid, lt_pref;
        int r;

        if (be16toh(option->len) + offsetof(DHCP6Option, data) < sizeof(*pdprefix_option))
                return -ENOBUFS;

        lt_valid = be32toh(pdprefix_option->iapdprefix.lifetime_valid);
        lt_pref = be32toh(pdprefix_option->iapdprefix.lifetime_preferred);

        if (lt_valid == 0 || lt_pref > lt_valid) {
                log_dhcp6_client(client, "Valid lifetieme of a PD prefix is zero or preferred lifetime %d > valid lifetime %d",
                                 lt_pref, lt_valid);

                return 0;
        }

        if (be16toh(option->len) + offsetof(DHCP6Option, data) > sizeof(*pdprefix_option)) {
                r = dhcp6_option_parse_status((DHCP6Option *)pdprefix_option->options, be16toh(option->len) + offsetof(DHCP6Option, data) - sizeof(*pdprefix_option));
                if (r != 0)
                        return r < 0 ? r: 0;
        }

        prefix = new0(DHCP6Address, 1);
        if (!prefix)
                return -ENOMEM;

        LIST_INIT(addresses, prefix);
        memcpy(&prefix->iapdprefix, option->data, sizeof(prefix->iapdprefix));

        LIST_PREPEND(addresses, ia->addresses, prefix);

        *lifetime_valid = be32toh(prefix->iapdprefix.lifetime_valid);

        return 0;
}

int dhcp6_option_parse_ia(DHCP6Option *iaoption, DHCP6IA *ia) {
        uint16_t iatype, optlen;
        size_t i, len;
        int r = 0, status;
        uint16_t opt;
        size_t iaaddr_offset;
        uint32_t lt_t1, lt_t2, lt_valid = 0, lt_min = UINT32_MAX;

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
                        log_dhcp6_client(client, "IA NA T1 %ds > T2 %ds",
                                         lt_t1, lt_t2);
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
                        log_dhcp6_client(client, "IA PD T1 %ds > T2 %ds",
                                         lt_t1, lt_t2);
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
                        if (r < 0)
                                return r;

                        if (lt_valid < lt_min)
                                lt_min = lt_valid;

                        break;

                case SD_DHCP6_OPTION_IA_PD_PREFIX:

                        if (!IN_SET(ia->type, SD_DHCP6_OPTION_IA_PD)) {
                                log_dhcp6_client(client, "IA PD Prefix option not in IA PD option");
                                return -EINVAL;
                        }

                        r = dhcp6_option_parse_pdprefix(option, ia, &lt_valid);
                        if (r < 0)
                                return r;

                        if (lt_valid < lt_min)
                                lt_min = lt_valid;

                        break;

                case SD_DHCP6_OPTION_STATUS_CODE:

                        status = dhcp6_option_parse_status(option, optlen + offsetof(DHCP6Option, data));
                        if (status < 0)
                                return status;
                        if (status > 0) {
                                log_dhcp6_client(client, "IA status %d",
                                                 status);

                                return -EINVAL;
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
                if (!ia->ia_na.lifetime_t1 && !ia->ia_na.lifetime_t2) {
                        lt_t1 = lt_min / 2;
                        lt_t2 = lt_min / 10 * 8;
                        ia->ia_na.lifetime_t1 = htobe32(lt_t1);
                        ia->ia_na.lifetime_t2 = htobe32(lt_t2);

                        log_dhcp6_client(client, "Computed IA NA T1 %ds and T2 %ds as both were zero",
                                         lt_t1, lt_t2);
                }

                break;

        case SD_DHCP6_OPTION_IA_PD:
                if (!ia->ia_pd.lifetime_t1 && !ia->ia_pd.lifetime_t2) {
                        lt_t1 = lt_min / 2;
                        lt_t2 = lt_min / 10 * 8;
                        ia->ia_pd.lifetime_t1 = htobe32(lt_t1);
                        ia->ia_pd.lifetime_t2 = htobe32(lt_t2);

                        log_dhcp6_client(client, "Computed IA PD T1 %ds and T2 %ds as both were zero",
                                         lt_t1, lt_t2);
                }

                break;

        default:
                break;
        }

        return 0;
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

int dhcp6_option_parse_domainname(const uint8_t *optval, uint16_t optlen, char ***str_arr) {
        size_t pos = 0, idx = 0;
        _cleanup_strv_free_ char **names = NULL;
        int r;

        assert_return(optlen > 1, -ENODATA);
        assert_return(optval[optlen - 1] == '\0', -EINVAL);

        while (pos < optlen) {
                _cleanup_free_ char *ret = NULL;
                size_t n = 0, allocated = 0;
                bool first = true;

                for (;;) {
                        const char *label;
                        uint8_t c;

                        c = optval[pos++];

                        if (c == 0)
                                /* End of name */
                                break;
                        if (c > 63)
                                return -EBADMSG;

                        /* Literal label */
                        label = (const char *)&optval[pos];
                        pos += c;
                        if (pos >= optlen)
                                return -EMSGSIZE;

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

                if (n == 0)
                        continue;

                if (!GREEDY_REALLOC(ret, allocated, n + 1))
                        return -ENOMEM;

                ret[n] = 0;

                r = strv_extend(&names, ret);
                if (r < 0)
                        return r;

                idx++;
        }

        *str_arr = TAKE_PTR(names);

        return idx;
}
