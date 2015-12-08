/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2008-2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <nss.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "hostname-util.h"
#include "local-addresses.h"
#include "macro.h"
#include "nss-util.h"
#include "string-util.h"
#include "util.h"

/* We use 127.0.0.2 as IPv4 address. This has the advantage over
 * 127.0.0.1 that it can be translated back to the local hostname. For
 * IPv6 we use ::1 which unfortunately will not translate back to the
 * hostname but instead something like "localhost" or so. */

#define LOCALADDRESS_IPV4 (htonl(0x7F000002))
#define LOCALADDRESS_IPV6 &in6addr_loopback

NSS_GETHOSTBYNAME_PROTOTYPES(myhostname);
NSS_GETHOSTBYADDR_PROTOTYPES(myhostname);

enum nss_status _nss_myhostname_gethostbyname4_r(
                const char *name,
                struct gaih_addrtuple **pat,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        struct gaih_addrtuple *r_tuple, *r_tuple_prev = NULL;
        _cleanup_free_ struct local_address *addresses = NULL;
        _cleanup_free_ char *hn = NULL;
        const char *canonical = NULL;
        int n_addresses = 0, lo_ifi;
        uint32_t local_address_ipv4;
        struct local_address *a;
        size_t l, idx, ms;
        char *r_name;
        unsigned n;

        assert(name);
        assert(pat);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        if (is_localhost(name)) {
                /* We respond to 'localhost', so that /etc/hosts
                 * is optional */

                canonical = "localhost";
                local_address_ipv4 = htonl(INADDR_LOOPBACK);

        } else if (is_gateway_hostname(name)) {

                n_addresses = local_gateways(NULL, 0, AF_UNSPEC, &addresses);
                if (n_addresses <= 0) {
                        *errnop = ENOENT;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                canonical = "gateway";

        } else {
                hn = gethostname_malloc();
                if (!hn) {
                        *errnop = ENOMEM;
                        *h_errnop = NO_RECOVERY;
                        return NSS_STATUS_TRYAGAIN;
                }

                /* We respond to our local host name, our our hostname suffixed with a single dot. */
                if (!streq(name, hn) && !streq_ptr(startswith(name, hn), ".")) {
                        *errnop = ENOENT;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                n_addresses = local_addresses(NULL, 0, AF_UNSPEC, &addresses);
                if (n_addresses < 0)
                        n_addresses = 0;

                canonical = hn;
                local_address_ipv4 = LOCALADDRESS_IPV4;
        }

        /* If this call fails we fill in 0 as scope. Which is fine */
        lo_ifi = n_addresses <= 0 ? LOOPBACK_IFINDEX : 0;

        l = strlen(canonical);
        ms = ALIGN(l+1) + ALIGN(sizeof(struct gaih_addrtuple)) * (n_addresses > 0 ? n_addresses : 2);
        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, fill in hostname */
        r_name = buffer;
        memcpy(r_name, canonical, l+1);
        idx = ALIGN(l+1);

        if (n_addresses <= 0) {
                /* Second, fill in IPv6 tuple */
                r_tuple = (struct gaih_addrtuple*) (buffer + idx);
                r_tuple->next = r_tuple_prev;
                r_tuple->name = r_name;
                r_tuple->family = AF_INET6;
                memcpy(r_tuple->addr, LOCALADDRESS_IPV6, 16);
                r_tuple->scopeid = (uint32_t) lo_ifi;

                idx += ALIGN(sizeof(struct gaih_addrtuple));
                r_tuple_prev = r_tuple;

                /* Third, fill in IPv4 tuple */
                r_tuple = (struct gaih_addrtuple*) (buffer + idx);
                r_tuple->next = r_tuple_prev;
                r_tuple->name = r_name;
                r_tuple->family = AF_INET;
                *(uint32_t*) r_tuple->addr = local_address_ipv4;
                r_tuple->scopeid = (uint32_t) lo_ifi;

                idx += ALIGN(sizeof(struct gaih_addrtuple));
                r_tuple_prev = r_tuple;
        }

        /* Fourth, fill actual addresses in, but in backwards order */
        for (a = addresses + n_addresses - 1, n = 0; (int) n < n_addresses; n++, a--) {
                r_tuple = (struct gaih_addrtuple*) (buffer + idx);
                r_tuple->next = r_tuple_prev;
                r_tuple->name = r_name;
                r_tuple->family = a->family;
                r_tuple->scopeid = a->ifindex;
                memcpy(r_tuple->addr, &a->address, 16);

                idx += ALIGN(sizeof(struct gaih_addrtuple));
                r_tuple_prev = r_tuple;
        }

        /* Verify the size matches */
        assert(idx == ms);

        /* Nscd expects us to store the first record in **pat. */
        if (*pat)
                **pat = *r_tuple_prev;
        else
                *pat = r_tuple_prev;

        if (ttlp)
                *ttlp = 0;

        /* Explicitly reset all error variables */
        *errnop = 0;
        *h_errnop = NETDB_SUCCESS;
        h_errno = 0;

        return NSS_STATUS_SUCCESS;
}

static enum nss_status fill_in_hostent(
                const char *canonical, const char *additional,
                int af,
                struct local_address *addresses, unsigned n_addresses,
                uint32_t local_address_ipv4,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

        size_t l_canonical, l_additional, idx, ms, alen;
        char *r_addr, *r_name, *r_aliases, *r_alias = NULL, *r_addr_list;
        struct local_address *a;
        unsigned n, c;

        assert(canonical);
        assert(result);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        alen = FAMILY_ADDRESS_SIZE(af);

        for (a = addresses, n = 0, c = 0; n < n_addresses; a++, n++)
                if (af == a->family)
                        c++;

        l_canonical = strlen(canonical);
        l_additional = additional ? strlen(additional) : 0;
        ms = ALIGN(l_canonical+1)+
                (additional ? ALIGN(l_additional+1) : 0) +
                sizeof(char*) +
                (additional ? sizeof(char*) : 0) +
                (c > 0 ? c : 1) * ALIGN(alen) +
                (c > 0 ? c+1 : 2) * sizeof(char*);

        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, fill in hostnames */
        r_name = buffer;
        memcpy(r_name, canonical, l_canonical+1);
        idx = ALIGN(l_canonical+1);

        if (additional) {
                r_alias = buffer + idx;
                memcpy(r_alias, additional, l_additional+1);
                idx += ALIGN(l_additional+1);
        }

        /* Second, create aliases array */
        r_aliases = buffer + idx;
        if (additional) {
                ((char**) r_aliases)[0] = r_alias;
                ((char**) r_aliases)[1] = NULL;
                idx += 2*sizeof(char*);
        } else {
                ((char**) r_aliases)[0] = NULL;
                idx += sizeof(char*);
        }

        /* Third, add addresses */
        r_addr = buffer + idx;
        if (c > 0) {
                unsigned i = 0;

                for (a = addresses, n = 0; n < n_addresses; a++, n++) {
                        if (af != a->family)
                                continue;

                        memcpy(r_addr + i*ALIGN(alen), &a->address, alen);
                        i++;
                }

                assert(i == c);
                idx += c*ALIGN(alen);
        } else {
                if (af == AF_INET)
                        *(uint32_t*) r_addr = local_address_ipv4;
                else
                        memcpy(r_addr, LOCALADDRESS_IPV6, 16);

                idx += ALIGN(alen);
        }

        /* Fourth, add address pointer array */
        r_addr_list = buffer + idx;
        if (c > 0) {
                unsigned i;

                for (i = 0; i < c; i++)
                        ((char**) r_addr_list)[i] = r_addr + i*ALIGN(alen);

                ((char**) r_addr_list)[i] = NULL;
                idx += (c+1) * sizeof(char*);

        } else {
                ((char**) r_addr_list)[0] = r_addr;
                ((char**) r_addr_list)[1] = NULL;
                idx += 2 * sizeof(char*);
        }

        /* Verify the size matches */
        assert(idx == ms);

        result->h_name = r_name;
        result->h_aliases = (char**) r_aliases;
        result->h_addrtype = af;
        result->h_length = alen;
        result->h_addr_list = (char**) r_addr_list;

        if (ttlp)
                *ttlp = 0;

        if (canonp)
                *canonp = r_name;

        /* Explicitly reset all error variables */
        *errnop = 0;
        *h_errnop = NETDB_SUCCESS;
        h_errno = 0;

        return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_myhostname_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

        _cleanup_free_ struct local_address *addresses = NULL;
        const char *canonical, *additional = NULL;
        _cleanup_free_ char *hn = NULL;
        uint32_t local_address_ipv4 = 0;
        int n_addresses = 0;

        assert(name);
        assert(host);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        if (af == AF_UNSPEC)
                af = AF_INET;

        if (af != AF_INET && af != AF_INET6) {
                *errnop = EAFNOSUPPORT;
                *h_errnop = NO_DATA;
                return NSS_STATUS_UNAVAIL;
        }

        if (is_localhost(name)) {
                canonical = "localhost";
                local_address_ipv4 = htonl(INADDR_LOOPBACK);

        } else if (is_gateway_hostname(name)) {

                n_addresses = local_gateways(NULL, 0, af, &addresses);
                if (n_addresses <= 0) {
                        *errnop = ENOENT;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                canonical = "gateway";

        } else {
                hn = gethostname_malloc();
                if (!hn) {
                        *errnop = ENOMEM;
                        *h_errnop = NO_RECOVERY;
                        return NSS_STATUS_TRYAGAIN;
                }

                if (!streq(name, hn) && !streq_ptr(startswith(name, hn), ".")) {
                        *errnop = ENOENT;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                n_addresses = local_addresses(NULL, 0, af, &addresses);
                if (n_addresses < 0)
                        n_addresses = 0;

                canonical = hn;
                additional = n_addresses <= 0 && af == AF_INET6 ? "localhost" : NULL;
                local_address_ipv4 = LOCALADDRESS_IPV4;
        }

        return fill_in_hostent(
                        canonical, additional,
                        af,
                        addresses, n_addresses,
                        local_address_ipv4,
                        host,
                        buffer, buflen,
                        errnop, h_errnop,
                        ttlp,
                        canonp);
}

enum nss_status _nss_myhostname_gethostbyaddr2_r(
                const void* addr, socklen_t len,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        const char *canonical = NULL, *additional = NULL;
        uint32_t local_address_ipv4 = LOCALADDRESS_IPV4;
        _cleanup_free_ struct local_address *addresses = NULL;
        _cleanup_free_ char *hn = NULL;
        int n_addresses = 0;
        struct local_address *a;
        bool additional_from_hostname = false;
        unsigned n;

        assert(addr);
        assert(host);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        if (!IN_SET(af, AF_INET, AF_INET6)) {
                *errnop = EAFNOSUPPORT;
                *h_errnop = NO_DATA;
                return NSS_STATUS_UNAVAIL;
        }

        if (len != FAMILY_ADDRESS_SIZE(af)) {
                *errnop = EINVAL;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        if (af == AF_INET) {
                if ((*(uint32_t*) addr) == LOCALADDRESS_IPV4)
                        goto found;

                if ((*(uint32_t*) addr) == htonl(INADDR_LOOPBACK)) {
                        canonical = "localhost";
                        local_address_ipv4 = htonl(INADDR_LOOPBACK);
                        goto found;
                }

        } else {
                assert(af == AF_INET6);

                if (memcmp(addr, LOCALADDRESS_IPV6, 16) == 0) {
                        canonical = "localhost";
                        additional_from_hostname = true;
                        goto found;
                }
        }

        n_addresses = local_addresses(NULL, 0, AF_UNSPEC, &addresses);
        if (n_addresses > 0) {
                for (a = addresses, n = 0; (int) n < n_addresses; n++, a++) {
                        if (af != a->family)
                                continue;

                        if (memcmp(addr, &a->address, FAMILY_ADDRESS_SIZE(af)) == 0)
                                goto found;
                }
        }

        addresses = mfree(addresses);

        n_addresses = local_gateways(NULL, 0, AF_UNSPEC, &addresses);
        if (n_addresses > 0) {
                for (a = addresses, n = 0; (int) n < n_addresses; n++, a++) {
                        if (af != a->family)
                                continue;

                        if (memcmp(addr, &a->address, FAMILY_ADDRESS_SIZE(af)) == 0) {
                                canonical = "gateway";
                                goto found;
                        }
                }
        }

        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;

        return NSS_STATUS_NOTFOUND;

found:
        if (!canonical || (!additional && additional_from_hostname)) {
                hn = gethostname_malloc();
                if (!hn) {
                        *errnop = ENOMEM;
                        *h_errnop = NO_RECOVERY;
                        return NSS_STATUS_TRYAGAIN;
                }

                if (!canonical)
                        canonical = hn;

                if (!additional && additional_from_hostname)
                        additional = hn;
        }

        return fill_in_hostent(
                        canonical, additional,
                        af,
                        addresses, n_addresses,
                        local_address_ipv4,
                        host,
                        buffer, buflen,
                        errnop, h_errnop,
                        ttlp,
                        NULL);
}

NSS_GETHOSTBYNAME_FALLBACKS(myhostname);
NSS_GETHOSTBYADDR_FALLBACKS(myhostname);
