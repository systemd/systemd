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

#include <nss.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "sd-bus.h"
#include "bus-util.h"
#include "bus-common-errors.h"
#include "macro.h"
#include "nss-util.h"
#include "util.h"
#include "in-addr-util.h"

NSS_GETHOSTBYNAME_PROTOTYPES(resolve);
NSS_GETHOSTBYADDR_PROTOTYPES(resolve);

#define DNS_CALL_TIMEOUT_USEC (45*USEC_PER_SEC)

typedef void (*voidfunc_t)(void);

static voidfunc_t find_fallback(const char *module, const char *symbol) {
        void *dl;

        /* Try to find a fallback NSS module symbol */

        dl = dlopen(module, RTLD_LAZY|RTLD_NODELETE);
        if (!dl)
                return NULL;

        return dlsym(dl, symbol);
}

static bool bus_error_shall_fallback(sd_bus_error *e) {
        return sd_bus_error_has_name(e, SD_BUS_ERROR_SERVICE_UNKNOWN) ||
               sd_bus_error_has_name(e, SD_BUS_ERROR_NAME_HAS_NO_OWNER) ||
               sd_bus_error_has_name(e, SD_BUS_ERROR_NO_REPLY) ||
               sd_bus_error_has_name(e, SD_BUS_ERROR_ACCESS_DENIED);
}

static int count_addresses(sd_bus_message *m, int af, const char **canonical) {
        int c = 0, r, ifindex;

        assert(m);
        assert(canonical);

        r = sd_bus_message_read(m, "i", &ifindex);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(m, 'a', "(iay)");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_enter_container(m, 'r', "iay")) > 0) {
                int family;

                r = sd_bus_message_read(m, "i", &family);
                if (r < 0)
                        return r;

                r = sd_bus_message_skip(m, "ay");
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

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "s", canonical);
        if (r < 0)
                return r;

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return r;

        return c;
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
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        const char *canonical = NULL;
        size_t l, ms, idx;
        char *r_name;
        int c, r, i = 0, ifindex;

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

        r = sd_bus_message_append(req, "isit", 0, name, AF_UNSPEC, (uint64_t) 0);
        if (r < 0)
                goto fail;

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, _BUS_ERROR_DNS "NXDOMAIN")) {
                        *errnop = ESRCH;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                if (bus_error_shall_fallback(&error)) {

                        enum nss_status (*fallback)(
                                        const char *name,
                                        struct gaih_addrtuple **pat,
                                        char *buffer, size_t buflen,
                                        int *errnop, int *h_errnop,
                                        int32_t *ttlp);

                        fallback = (enum nss_status (*)(const char *name,
                                                        struct gaih_addrtuple **pat,
                                                        char *buffer, size_t buflen,
                                                        int *errnop, int *h_errnop,
                                                        int32_t *ttlp))
                                find_fallback("libnss_dns.so.2", "_nss_dns_gethostbyname4_r");
                        if (fallback)
                                return fallback(name, pat, buffer, buflen, errnop, h_errnop, ttlp);
                }

                *errnop = -r;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        c = count_addresses(reply, AF_UNSPEC, &canonical);
        if (c < 0) {
                r = c;
                goto fail;
        }
        if (c == 0) {
                *errnop = ESRCH;
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        if (isempty(canonical))
                canonical = name;

        l = strlen(canonical);
        ms = ALIGN(l+1) + ALIGN(sizeof(struct gaih_addrtuple)) * c;
        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = TRY_AGAIN;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, append name */
        r_name = buffer;
        memcpy(r_name, canonical, l+1);
        idx = ALIGN(l+1);

        /* Second, append addresses */
        r_tuple_first = (struct gaih_addrtuple*) (buffer + idx);

        r = sd_bus_message_read(reply, "i", &ifindex);
        if (r < 0)
                goto fail;

        if (ifindex < 0) {
                r = -EINVAL;
                goto fail;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(iay)");
        if (r < 0)
                goto fail;

        while ((r = sd_bus_message_enter_container(reply, 'r', "iay")) > 0) {
                int family;
                const void *a;
                size_t sz;

                r = sd_bus_message_read(reply, "i", &family);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        goto fail;

                if (!IN_SET(family, AF_INET, AF_INET6))
                        continue;

                if (sz != FAMILY_ADDRESS_SIZE(family)) {
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
        if (r < 0)
                goto fail;

        assert(i == c);
        assert(idx == ms);

        if (*pat)
                **pat = *r_tuple_first;
        else
                *pat = r_tuple_first;

        if (ttlp)
                *ttlp = 0;

        /* Explicitly reset all error variables */
        *errnop = 0;
        *h_errnop = NETDB_SUCCESS;
        h_errno = 0;

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
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        size_t l, idx, ms, alen;
        const char *canonical;
        int c, r, i = 0, ifindex;

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

        r = sd_bus_message_append(req, "isit", 0, name, af, (uint64_t) 0);
        if (r < 0)
                goto fail;

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, _BUS_ERROR_DNS "NXDOMAIN")) {
                        *errnop = ESRCH;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                if (bus_error_shall_fallback(&error)) {

                        enum nss_status (*fallback)(
                                        const char *name,
                                        int af,
                                        struct hostent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop, int *h_errnop,
                                        int32_t *ttlp,
                                        char **canonp);

                        fallback = (enum nss_status (*)(const char *name,
                                                        int af,
                                                        struct hostent *result,
                                                        char *buffer, size_t buflen,
                                                        int *errnop, int *h_errnop,
                                                        int32_t *ttlp,
                                                        char **canonp))
                                find_fallback("libnss_dns.so.2", "_nss_dns_gethostbyname3_r");
                        if (fallback)
                                return fallback(name, af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp);
                }

                *errnop = -r;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        c = count_addresses(reply, af, &canonical);
        if (c < 0) {
                r = c;
                goto fail;
        }
        if (c == 0) {
                *errnop = ESRCH;
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        if (isempty(canonical))
                canonical = name;

        alen = FAMILY_ADDRESS_SIZE(af);
        l = strlen(canonical);

        ms = ALIGN(l+1) + c * ALIGN(alen) + (c+2) * sizeof(char*);

        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = TRY_AGAIN;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, append name */
        r_name = buffer;
        memcpy(r_name, canonical, l+1);
        idx = ALIGN(l+1);

        /* Second, create empty aliases array */
        r_aliases = buffer + idx;
        ((char**) r_aliases)[0] = NULL;
        idx += sizeof(char*);

        /* Third, append addresses */
        r_addr = buffer + idx;

        r = sd_bus_message_read(reply, "i", &ifindex);
        if (r < 0)
                goto fail;

        if (ifindex < 0) {
                r = -EINVAL;
                goto fail;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(iay)");
        if (r < 0)
                goto fail;

        while ((r = sd_bus_message_enter_container(reply, 'r', "iay")) > 0) {
                int family;
                const void *a;
                size_t sz;

                r = sd_bus_message_read(reply, "i", &family);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
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

                memcpy(r_addr + i*ALIGN(alen), a, alen);
                i++;
        }
        if (r < 0)
                goto fail;

        assert(i == c);
        idx += c * ALIGN(alen);

        /* Fourth, append address pointer array */
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

        /* Explicitly reset all error variables */
        *errnop = 0;
        *h_errnop = NETDB_SUCCESS;
        h_errno = 0;

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
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        unsigned c = 0, i = 0;
        size_t ms = 0, idx;
        const char *n;
        int r, ifindex;

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

        if (len != FAMILY_ADDRESS_SIZE(af)) {
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

        r = sd_bus_message_append(req, "ii", 0, af);
        if (r < 0)
                goto fail;

        r = sd_bus_message_append_array(req, 'y', addr, len);
        if (r < 0)
                goto fail;

        r = sd_bus_message_append(req, "t", (uint64_t) 0);
        if (r < 0)
                goto fail;

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, _BUS_ERROR_DNS "NXDOMAIN")) {
                        *errnop = ESRCH;
                        *h_errnop = HOST_NOT_FOUND;
                        return NSS_STATUS_NOTFOUND;
                }

                if (bus_error_shall_fallback(&error)) {

                        enum nss_status (*fallback)(
                                        const void* addr, socklen_t len,
                                        int af,
                                        struct hostent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop, int *h_errnop,
                                        int32_t *ttlp);

                        fallback = (enum nss_status (*)(
                                        const void* addr, socklen_t len,
                                        int af,
                                        struct hostent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop, int *h_errnop,
                                        int32_t *ttlp))
                                find_fallback("libnss_dns.so.2", "_nss_dns_gethostbyaddr2_r");

                        if (fallback)
                                return fallback(addr, len, af, result, buffer, buflen, errnop, h_errnop, ttlp);
                }

                *errnop = -r;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
        }

        r = sd_bus_message_read(reply, "i", &ifindex);
        if (r < 0)
                goto fail;

        if (ifindex < 0) {
                r = -EINVAL;
                goto fail;
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
        if (r < 0)
                goto fail;

        ((char**) r_aliases)[c-1] = NULL;
        assert(idx == ms);

        result->h_name = r_name;
        result->h_aliases = (char**) r_aliases;
        result->h_addrtype = af;
        result->h_length = len;
        result->h_addr_list = (char**) r_addr_list;

        if (ttlp)
                *ttlp = 0;

        /* Explicitly reset all error variables */
        *errnop = 0;
        *h_errnop = NETDB_SUCCESS;
        h_errno = 0;

        return NSS_STATUS_SUCCESS;

fail:
        *errnop = -r;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
}

NSS_GETHOSTBYNAME_FALLBACKS(resolve);
NSS_GETHOSTBYADDR_FALLBACKS(resolve);
