/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <limits.h>
#include <nss.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "sd-bus.h"
#include "bus-util.h"
#include "bus-errors.h"
#include "macro.h"
#include "nss-util.h"
#include "util.h"
#include "in-addr-util.h"

NSS_GETHOSTBYNAME_PROTOTYPES(resolve);
NSS_GETHOSTBYADDR_PROTOTYPES(resolve);

#define DNS_CALL_TIMEOUT_USEC (45*USEC_PER_SEC)

static int count_addresses(sd_bus_message *m, unsigned af, unsigned *ret) {
        unsigned c = 0;
        int r;

        assert(m);
        assert(ret);

        while ((r = sd_bus_message_enter_container(m, 'r', "yayi")) > 0) {
                unsigned char family;

                r = sd_bus_message_read(m, "y", &family);
                if (r < 0)
                        return r;

                r = sd_bus_message_skip(m, "ayi");
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;

                if (af != AF_UNSPEC && family != af)
                        continue;

                c ++;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_rewind(m, false);
        if (r < 0)
                return r;

        *ret = c;
        return 0;
}

enum nss_status _nss_resolve_gethostbyname4_r(
                const char *name,
                struct gaih_addrtuple **pat,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        _cleanup_bus_message_unref_ sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        struct gaih_addrtuple *r_tuple, *r_tuple_first = NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        size_t l, ms, idx;
        char *r_name;
        unsigned i = 0, c = 0;
        int r;

        assert(name);
        assert(pat);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "ResolveHostname");
        if (r < 0)
                goto fail;

        r = sd_bus_message_set_auto_start(req, false);
        if (r < 0)
                goto fail;

        r = sd_bus_message_append(req, "sy", name, AF_UNSPEC);
        if (r < 0)
                goto fail;

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, _BUS_ERROR_DNS "NXDOMAIN")) {
                        *errnop = ESRCH;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                *errnop = -r;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(yayi)");
        if (r < 0)
                goto fail;

        r = count_addresses(reply, AF_UNSPEC, &c);
        if (r < 0)
                goto fail;

        if (c <= 0) {
                *errnop = ESRCH;
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        l = strlen(name);
        ms = ALIGN(l+1) + ALIGN(sizeof(struct gaih_addrtuple)) * c;
        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = TRY_AGAIN;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, append name */
        r_name = buffer;
        memcpy(r_name, name, l+1);
        idx = ALIGN(l+1);

        /* Second, append addresses */
        r_tuple_first = (struct gaih_addrtuple*) (buffer + idx);
        while ((r = sd_bus_message_enter_container(reply, 'r', "yayi")) > 0) {
                unsigned char family;
                const void *a;
                int ifindex;
                size_t sz;

                r = sd_bus_message_read(reply, "y", &family);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_read(reply, "i", &ifindex);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        goto fail;

                if (!IN_SET(family, AF_INET, AF_INET6))
                        continue;

                if (sz != PROTO_ADDRESS_SIZE(family)) {
                        r = -EINVAL;
                        goto fail;
                }

                if (ifindex < 0) {
                        r = -EINVAL;
                        goto fail;
                }

                r_tuple = (struct gaih_addrtuple*) (buffer + idx);
                r_tuple->next = i == c-1 ? NULL : (struct gaih_addrtuple*) ((char*) r_tuple + ALIGN(sizeof(struct gaih_addrtuple)));
                r_tuple->name = r_name;
                r_tuple->family = family;
                r_tuple->scopeid = ifindex;
                memcpy(r_tuple->addr, a, sz);

                idx += ALIGN(sizeof(struct gaih_addrtuple));
                i++;
        }

        assert(i == c);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto fail;

        assert(idx == ms);

        if (*pat)
                **pat = *r_tuple_first;
        else
                *pat = r_tuple_first;

        if (ttlp)
                *ttlp = 0;

        return NSS_STATUS_SUCCESS;

fail:
        *errnop = -r;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_resolve_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

        _cleanup_bus_message_unref_ sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        char *r_name, *r_aliases, *r_addr, *r_addr_list;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        unsigned c = 0, i = 0;
        size_t l, idx, ms, alen;
        int r;

        assert(name);
        assert(result);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        if (af == AF_UNSPEC)
                af = AF_INET;

        if (af != AF_INET && af != AF_INET6) {
                r = -EAFNOSUPPORT;
                goto fail;
        }

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "ResolveHostname");
        if (r < 0)
                goto fail;

        r = sd_bus_message_set_auto_start(req, false);
        if (r < 0)
                goto fail;

        r = sd_bus_message_append(req, "sy", name, af);
        if (r < 0)
                goto fail;

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, _BUS_ERROR_DNS "NXDOMAIN")) {
                        *errnop = ESRCH;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                *errnop = -r;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(yayi)");
        if (r < 0)
                goto fail;

        r = count_addresses(reply, af, &c);
        if (r < 0)
                goto fail;

        if (c <= 0) {
                *errnop = ESRCH;
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        alen = PROTO_ADDRESS_SIZE(af);
        l = strlen(name);

        ms = ALIGN(l+1) +
                sizeof(char*) +
                (c > 0 ? c : 1) * ALIGN(alen) +
                (c > 0 ? c+1 : 2) * sizeof(char*);

        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = TRY_AGAIN;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, append name */
        r_name = buffer;
        memcpy(r_name, name, l+1);
        idx = ALIGN(l+1);

        /* Second, create aliases array */
        r_aliases = buffer + idx;
        ((char**) r_aliases)[0] = NULL;
        idx += sizeof(char*);

        /* Third, append addresses */
        r_addr = buffer + idx;
        while ((r = sd_bus_message_enter_container(reply, 'r', "yayi")) > 0) {
                unsigned char family;
                const void *a;
                int ifindex;
                size_t sz;

                r = sd_bus_message_read(reply, "y", &family);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_read(reply, "i", &ifindex);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        goto fail;

                if (family != af)
                        continue;

                if (sz != alen) {
                        r = -EINVAL;
                        goto fail;
                }

                if (ifindex < 0) {
                        r = -EINVAL;
                        goto fail;
                }

                memcpy(r_addr + i*ALIGN(alen), a, alen);
                i++;
        }

        assert(i == c);
        idx += c * ALIGN(alen);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto fail;

        /* Third, append address pointer array */
        r_addr_list = buffer + idx;
        for (i = 0; i < c; i++)
                ((char**) r_addr_list)[i] = r_addr + i*ALIGN(alen);

        ((char**) r_addr_list)[i] = NULL;
        idx += (c+1) * sizeof(char*);

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

fail:
        *errnop = -r;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_resolve_gethostbyaddr2_r(
                const void* addr, socklen_t len,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        _cleanup_bus_message_unref_ sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        char *r_name, *r_aliases, *r_addr, *r_addr_list;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        unsigned c = 0, i = 0;
        size_t ms = 0, idx;
        const char *n;
        int r;

        assert(addr);
        assert(result);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        if (!IN_SET(af, AF_INET, AF_INET6)) {
                *errnop = EAFNOSUPPORT;
                *h_errnop = NO_DATA;
                return NSS_STATUS_UNAVAIL;
        }

        if (len != PROTO_ADDRESS_SIZE(af)) {
                *errnop = EINVAL;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "ResolveAddress");
        if (r < 0)
                goto fail;

        r = sd_bus_message_set_auto_start(req, false);
        if (r < 0)
                goto fail;

        r = sd_bus_message_append(req, "y", af);
        if (r < 0)
                goto fail;

        r = sd_bus_message_append_array(req, 'y', addr, len);
        if (r < 0)
                goto fail;

        r = sd_bus_message_append(req, "i", 0);
        if (r < 0)
                goto fail;

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, _BUS_ERROR_DNS "NXDOMAIN")) {
                        *errnop = ESRCH;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                *errnop = -r;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        r = sd_bus_message_enter_container(reply, 'a', "s");
        if (r < 0)
                goto fail;

        while ((r = sd_bus_message_read(reply, "s", &n)) > 0) {
                c++;
                ms += ALIGN(strlen(n) + 1);
        }
        if (r < 0)
                goto fail;

        r = sd_bus_message_rewind(reply, false);
        if (r < 0)
                return r;

        if (c <= 0) {
                *errnop = ESRCH;
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        ms += ALIGN(len) +              /* the address */
              2 * sizeof(char*) +       /* pointers to the address, plus trailing NULL */
              c * sizeof(char*);        /* pointers to aliases, plus trailing NULL */

        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = TRY_AGAIN;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, place address */
        r_addr = buffer;
        memcpy(r_addr, addr, len);
        idx = ALIGN(len);

        /* Second, place address list */
        r_addr_list = buffer + idx;
        ((char**) r_addr_list)[0] = r_addr;
        ((char**) r_addr_list)[1] = NULL;
        idx += sizeof(char*) * 2;

        /* Third, reserve space for the aliases array */
        r_aliases = buffer + idx;
        idx += sizeof(char*) * c;

        /* Fourth, place aliases */
        i = 0;
        r_name = buffer + idx;
        while ((r = sd_bus_message_read(reply, "s", &n)) > 0) {
                char *p;
                size_t l;

                l = strlen(n);
                p = buffer + idx;
                memcpy(p, n, l+1);

                if (i > 1)
                        ((char**) r_aliases)[i-1] = p;
                i++;

                idx += ALIGN(l+1);
        }

        ((char**) r_aliases)[c-1] = NULL;
        assert(idx == ms);

        result->h_name = r_name;
        result->h_aliases = (char**) r_aliases;
        result->h_addrtype = af;
        result->h_length = len;
        result->h_addr_list = (char**) r_addr_list;

        if (ttlp)
                *ttlp = 0;

        return NSS_STATUS_SUCCESS;

fail:
        *errnop = -r;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
}

NSS_GETHOSTBYNAME_FALLBACKS(resolve);
NSS_GETHOSTBYADDR_FALLBACKS(resolve);
