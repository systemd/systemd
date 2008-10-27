/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
    This file is part of nss-myhostname.

    Copyright 2008 Lennart Poettering

    nss-myhostname is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 2.1
    of the License, or (at your option) any later version.

    nss-myhostname is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with nss-myhostname. If not, If not, see
    <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <limits.h>
#include <nss.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <net/if.h>

/* We use 127.0.0.2 as IPv4 address. This has the advantage over
 * 127.0.0.1 that it can be translated back to the local hostname. For
 * IPv6 we use ::1 which unfortunately will not translate back to the
 * hostname but instead something like "localhost6" or so. */

#define LOCALADDRESS_IPV4 (htonl(0x7F000002))
#define LOCALADDRESS_IPV6 &in6addr_loopback
#define LOOPBACK_INTERFACE "lo"

#define ALIGN(a) (((a+sizeof(void*)-1)/sizeof(void*))*sizeof(void*))

enum nss_status _nss_myhostname_gethostbyname4_r(
                const char *name,
                struct gaih_addrtuple **pat,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        unsigned ifi;
        char hn[HOST_NAME_MAX+1];
        size_t l, idx, ms;
        char *r_name;
        struct gaih_addrtuple *r_tuple1, *r_tuple2;

        memset(hn, 0, sizeof(hn));
        if (gethostname(hn, sizeof(hn)-1) < 0) {
                *errnop = errno;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        if (strcasecmp(name, hn) != 0) {
                *errnop = ENOENT;
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        /* If this call fails we fill in 0 as scope. Which is fine */
        ifi = if_nametoindex(LOOPBACK_INTERFACE);

        l = strlen(hn);
        ms = ALIGN(l+1)+ALIGN(sizeof(struct gaih_addrtuple))*2;
        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, fill in hostname */
        r_name = buffer;
        memcpy(r_name, hn, l+1);
        idx = ALIGN(l+1);

        /* Second, fill in IPv4 tuple */
        r_tuple1 = (struct gaih_addrtuple*) (buffer + idx);
        r_tuple1->next = NULL;
        r_tuple1->name = r_name;
        r_tuple1->family = AF_INET;
        *(uint32_t*) r_tuple1->addr = LOCALADDRESS_IPV4;
        r_tuple1->scopeid = (uint32_t) ifi;
        idx += ALIGN(sizeof(struct gaih_addrtuple));

        /* Third, fill in IPv6 tuple */
        r_tuple2 = (struct gaih_addrtuple*) (buffer + idx);
        r_tuple2->next = r_tuple1;
        r_tuple2->name = r_name;
        r_tuple2->family = AF_INET6;
        memcpy(r_tuple2->addr, LOCALADDRESS_IPV6, 16);
        r_tuple1->scopeid = (uint32_t) ifi;
        idx += ALIGN(sizeof(struct gaih_addrtuple));

        /* Verify the size matches */
        assert(idx == ms);

        *pat = r_tuple2;

        if (ttlp)
                *ttlp = 0;

        return NSS_STATUS_SUCCESS;
}

static enum nss_status fill_in_hostent(
                const char *hn,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

        size_t l, idx, ms;
        char *r_addr, *r_name, *r_aliases, *r_addr_list;
        size_t alen;

        alen = af == AF_INET ? 4 : 16;

        l = strlen(hn);
        ms = ALIGN(l+1)+sizeof(char*)+ALIGN(alen)+sizeof(char*)*2;
        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, fill in hostname */
        r_name = buffer;
        memcpy(r_name, hn, l+1);
        idx = ALIGN(l+1);

        /* Second, create aliases array */
        r_aliases = buffer + idx;
        *(char**) r_aliases = NULL;
        idx += sizeof(char*);

        /* Third, add address */
        r_addr = buffer + idx;
        if (af == AF_INET)
                *(uint32_t*) r_addr = LOCALADDRESS_IPV4;
        else
                memcpy(r_addr, LOCALADDRESS_IPV6, 16);
        idx += ALIGN(alen);

        /* Fourth, add address pointer array */
        r_addr_list = buffer + idx;
        ((char**) r_addr_list)[0] = r_addr;
        ((char**) r_addr_list)[1] = NULL;
        idx += sizeof(char*)*2;

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

        char hn[HOST_NAME_MAX+1];

        if (af == AF_UNSPEC)
                af = AF_INET;

        if (af != AF_INET && af != AF_INET6) {
                *errnop = EAFNOSUPPORT;
                *h_errnop = NO_DATA;
                return NSS_STATUS_UNAVAIL;
        }

        memset(hn, 0, sizeof(hn));
        if (gethostname(hn, sizeof(hn)-1) < 0) {
                *errnop = errno;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        if (strcasecmp(name, hn) != 0) {
                *errnop = ENOENT;
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        return fill_in_hostent(hn, af, host, buffer, buflen, errnop, h_errnop, ttlp, canonp);
}

enum nss_status _nss_myhostname_gethostbyname2_r(
                const char *name,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop) {

        return _nss_myhostname_gethostbyname3_r(
                        name,
                        af,
                        host,
                        buffer, buflen,
                        errnop, h_errnop,
                        NULL,
                        NULL);
}

enum nss_status _nss_myhostname_gethostbyname_r (
                const char *name,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop) {

        return _nss_myhostname_gethostbyname3_r(
                        name,
                        AF_UNSPEC,
                        host,
                        buffer, buflen,
                        errnop, h_errnop,
                        NULL,
                        NULL);
}

enum nss_status _nss_myhostname_gethostbyaddr2_r(
                const void* addr, socklen_t len,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        char hn[HOST_NAME_MAX+1];

        if (af == AF_INET) {
                if (len != 4 ||
                    (*(uint32_t*) addr) != LOCALADDRESS_IPV4)
                        goto not_found;

        } else if (af == AF_INET6) {
                if (len != 16 ||
                    memcmp(addr, LOCALADDRESS_IPV6, 16) != 0)
                        goto not_found;
        } else {
                *errnop = EAFNOSUPPORT;
                *h_errnop = NO_DATA;
                return NSS_STATUS_UNAVAIL;
        }

        memset(hn, 0, sizeof(hn));
        if (gethostname(hn, sizeof(hn)-1) < 0) {
                *errnop = errno;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        return fill_in_hostent(hn, af, host, buffer, buflen, errnop, h_errnop, ttlp, NULL);

not_found:
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_myhostname_gethostbyaddr_r(
                const void* addr, socklen_t len,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop) {

        return _nss_myhostname_gethostbyaddr2_r(
                        addr, len,
                        af,
                        host,
                        buffer, buflen,
                        errnop, h_errnop,
                        NULL);
}
