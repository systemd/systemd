/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <errno.h>

#include "alloc-util.h"
#include "dhcp6-lease-internal.h"
#include "dhcp6-protocol.h"
#include "strv.h"
#include "util.h"

int dhcp6_lease_ia_rebind_expire(const DHCP6IA *ia, uint32_t *expire) {
        DHCP6Address *addr;
        uint32_t valid = 0, t;

        assert_return(ia, -EINVAL);
        assert_return(expire, -EINVAL);

        LIST_FOREACH(addresses, addr, ia->addresses) {
                t = be32toh(addr->iaaddr.lifetime_valid);
                if (valid < t)
                        valid = t;
        }

        t = be32toh(ia->ia_na.lifetime_t2);
        if (t > valid)
                return -EINVAL;

        *expire = valid - t;

        return 0;
}

DHCP6IA *dhcp6_lease_free_ia(DHCP6IA *ia) {
        DHCP6Address *address;

        if (!ia)
                return NULL;

        while (ia->addresses) {
                address = ia->addresses;

                LIST_REMOVE(addresses, ia->addresses, address);

                free(address);
        }

        return NULL;
}

int dhcp6_lease_set_serverid(sd_dhcp6_lease *lease, const uint8_t *id,
                             size_t len) {
        uint8_t *serverid;

        assert_return(lease, -EINVAL);
        assert_return(id, -EINVAL);

        serverid = memdup(id, len);
        if (!serverid)
                return -ENOMEM;

        free_and_replace(lease->serverid, serverid);
        lease->serverid_len = len;

        return 0;
}

int dhcp6_lease_get_serverid(sd_dhcp6_lease *lease, uint8_t **id, size_t *len) {
        assert_return(lease, -EINVAL);

        if (!lease->serverid)
                return -ENOMSG;

        if (id)
                *id = lease->serverid;
        if (len)
                *len = lease->serverid_len;

        return 0;
}

int dhcp6_lease_set_preference(sd_dhcp6_lease *lease, uint8_t preference) {
        assert_return(lease, -EINVAL);

        lease->preference = preference;

        return 0;
}

int dhcp6_lease_get_preference(sd_dhcp6_lease *lease, uint8_t *preference) {
        assert_return(preference, -EINVAL);

        if (!lease)
                return -EINVAL;

        *preference = lease->preference;

        return 0;
}

int dhcp6_lease_set_rapid_commit(sd_dhcp6_lease *lease) {
        assert_return(lease, -EINVAL);

        lease->rapid_commit = true;

        return 0;
}

int dhcp6_lease_get_rapid_commit(sd_dhcp6_lease *lease, bool *rapid_commit) {
        assert_return(lease, -EINVAL);
        assert_return(rapid_commit, -EINVAL);

        *rapid_commit = lease->rapid_commit;

        return 0;
}

int dhcp6_lease_get_iaid(sd_dhcp6_lease *lease, be32_t *iaid) {
        assert_return(lease, -EINVAL);
        assert_return(iaid, -EINVAL);

        *iaid = lease->ia.ia_na.id;

        return 0;
}

int dhcp6_lease_get_pd_iaid(sd_dhcp6_lease *lease, be32_t *iaid) {
        assert_return(lease, -EINVAL);
        assert_return(iaid, -EINVAL);

        *iaid = lease->pd.ia_pd.id;

        return 0;
}

int sd_dhcp6_lease_get_address(sd_dhcp6_lease *lease, struct in6_addr *addr,
                               uint32_t *lifetime_preferred,
                               uint32_t *lifetime_valid) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(lifetime_preferred, -EINVAL);
        assert_return(lifetime_valid, -EINVAL);

        if (!lease->addr_iter)
                return -ENOMSG;

        memcpy(addr, &lease->addr_iter->iaaddr.address,
                sizeof(struct in6_addr));
        *lifetime_preferred =
                be32toh(lease->addr_iter->iaaddr.lifetime_preferred);
        *lifetime_valid = be32toh(lease->addr_iter->iaaddr.lifetime_valid);

        lease->addr_iter = lease->addr_iter->addresses_next;

        return 0;
}

void sd_dhcp6_lease_reset_address_iter(sd_dhcp6_lease *lease) {
        if (lease)
                lease->addr_iter = lease->ia.addresses;
}

int sd_dhcp6_lease_get_pd(sd_dhcp6_lease *lease, struct in6_addr *prefix,
                          uint8_t *prefix_len,
                          uint32_t *lifetime_preferred,
                          uint32_t *lifetime_valid) {
        assert_return(lease, -EINVAL);
        assert_return(prefix, -EINVAL);
        assert_return(prefix_len, -EINVAL);
        assert_return(lifetime_preferred, -EINVAL);
        assert_return(lifetime_valid, -EINVAL);

        if (!lease->prefix_iter)
                return -ENOMSG;

        memcpy(prefix, &lease->prefix_iter->iapdprefix.address,
               sizeof(struct in6_addr));
        *prefix_len = lease->prefix_iter->iapdprefix.prefixlen;
        *lifetime_preferred =
                be32toh(lease->prefix_iter->iapdprefix.lifetime_preferred);
        *lifetime_valid =
                be32toh(lease->prefix_iter->iapdprefix.lifetime_valid);

        lease->prefix_iter = lease->prefix_iter->addresses_next;

        return 0;
}

void sd_dhcp6_lease_reset_pd_prefix_iter(sd_dhcp6_lease *lease) {
        if (lease)
                lease->prefix_iter = lease->pd.addresses;
}

int dhcp6_lease_add_dns(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        assert_return(lease, -EINVAL);
        assert_return(optval, -EINVAL);

        if (optlen == 0)
                return 0;

        return dhcp6_option_parse_addresses(optval, optlen, &lease->dns, &lease->dns_count);
}

int sd_dhcp6_lease_get_dns(sd_dhcp6_lease *lease, const struct in6_addr **ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->dns)
                return -ENOENT;

        *ret = lease->dns;
        return lease->dns_count;
}

int dhcp6_lease_add_domains(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        _cleanup_strv_free_ char **domains = NULL;
        int r;

        assert_return(lease, -EINVAL);
        assert_return(optval, -EINVAL);

        if (optlen == 0)
                return 0;

        r = dhcp6_option_parse_domainname_list(optval, optlen, &domains);
        if (r < 0)
                return r;

        return strv_extend_strv(&lease->domains, domains, true);
}

int sd_dhcp6_lease_get_domains(sd_dhcp6_lease *lease, char ***ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->domains)
                return -ENOENT;

        *ret = lease->domains;
        return strv_length(lease->domains);
}

int dhcp6_lease_add_ntp(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        int r;

        assert_return(lease, -EINVAL);
        assert_return(optval, -EINVAL);

        for (size_t offset = 0; offset < optlen;) {
                const uint8_t *subval;
                size_t sublen;
                uint16_t subopt;

                r = dhcp6_option_parse(optval, optlen, &offset, &subopt, &sublen, &subval);
                if (r < 0)
                        return r;

                switch(subopt) {
                case DHCP6_NTP_SUBOPTION_SRV_ADDR:
                case DHCP6_NTP_SUBOPTION_MC_ADDR:
                        if (sublen != 16)
                                return 0;

                        r = dhcp6_option_parse_addresses(subval, sublen, &lease->ntp, &lease->ntp_count);
                        if (r < 0)
                                return r;

                        break;

                case DHCP6_NTP_SUBOPTION_SRV_FQDN: {
                        _cleanup_free_ char *server = NULL;

                        r = dhcp6_option_parse_domainname(subval, sublen, &server);
                        if (r < 0)
                                return r;

                        if (strv_contains(lease->ntp_fqdn, server))
                                continue;

                        r = strv_consume(&lease->ntp_fqdn, TAKE_PTR(server));
                        if (r < 0)
                                return r;

                        break;
                }}
        }

        return 0;
}

int dhcp6_lease_add_sntp(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        assert_return(lease, -EINVAL);
        assert_return(optval, -EINVAL);

        if (optlen == 0)
                return 0;

        /* SNTP option is defined in RFC4075, and deprecated by RFC5908. */
        return dhcp6_option_parse_addresses(optval, optlen, &lease->sntp, &lease->sntp_count);
}

int sd_dhcp6_lease_get_ntp_addrs(sd_dhcp6_lease *lease, const struct in6_addr **ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (lease->ntp) {
                *ret = lease->ntp;
                return lease->ntp_count;
        }

        if (lease->sntp && !lease->ntp_fqdn) {
                /* Fallback to the deprecated SNTP option. */
                *ret = lease->sntp;
                return lease->sntp_count;
        }

        return -ENOENT;
}

int sd_dhcp6_lease_get_ntp_fqdn(sd_dhcp6_lease *lease, char ***ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->ntp_fqdn)
                return -ENOENT;

        *ret = lease->ntp_fqdn;
        return strv_length(lease->ntp_fqdn);
}

int dhcp6_lease_set_fqdn(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        int r;
        char *fqdn;

        assert_return(lease, -EINVAL);
        assert_return(optval, -EINVAL);

        if (optlen < 2)
                return -ENODATA;

        /* Ignore the flags field, it doesn't carry any useful
           information for clients. */
        r = dhcp6_option_parse_domainname(optval + 1, optlen - 1, &fqdn);
        if (r < 0)
                return r;

        return free_and_replace(lease->fqdn, fqdn);
}

int sd_dhcp6_lease_get_fqdn(sd_dhcp6_lease *lease, const char **ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->fqdn)
                return -ENOENT;

        *ret = lease->fqdn;
        return 0;
}

static sd_dhcp6_lease *dhcp6_lease_free(sd_dhcp6_lease *lease) {
        if (!lease)
                return NULL;

        free(lease->serverid);
        dhcp6_lease_free_ia(&lease->ia);
        dhcp6_lease_free_ia(&lease->pd);
        free(lease->dns);
        free(lease->fqdn);
        strv_free(lease->domains);
        free(lease->ntp);
        strv_free(lease->ntp_fqdn);
        free(lease->sntp);

        return mfree(lease);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_lease, sd_dhcp6_lease, dhcp6_lease_free);

int dhcp6_lease_new(sd_dhcp6_lease **ret) {
        sd_dhcp6_lease *lease;

        lease = new0(sd_dhcp6_lease, 1);
        if (!lease)
                return -ENOMEM;

        lease->n_ref = 1;

        LIST_HEAD_INIT(lease->ia.addresses);

        *ret = lease;
        return 0;
}
