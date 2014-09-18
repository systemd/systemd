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

#include "sd-bus.h"
#include "sd-login.h"
#include "macro.h"
#include "util.h"
#include "nss-util.h"
#include "bus-util.h"
#include "in-addr-util.h"

NSS_GETHOSTBYNAME_PROTOTYPES(mymachines);

static int count_addresses(sd_bus_message *m, int af, unsigned *ret) {
        unsigned c = 0;
        int r;

        assert(m);
        assert(ret);

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

        r = sd_bus_message_rewind(m, false);
        if (r < 0)
                return r;

        *ret = c;
        return 0;
}

enum nss_status _nss_mymachines_gethostbyname4_r(
                const char *name,
                struct gaih_addrtuple **pat,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        struct gaih_addrtuple *r_tuple, *r_tuple_first = NULL;
        _cleanup_bus_message_unref_ sd_bus_message* reply = NULL;
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        _cleanup_free_ int *ifindices = NULL;
        _cleanup_free_ char *class = NULL;
        size_t l, ms, idx;
        unsigned i = 0, c = 0;
        char *r_name;
        int n_ifindices, r;

        assert(name);
        assert(pat);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        r = sd_machine_get_class(name, &class);
        if (r < 0)
                goto fail;
        if (!streq(class, "container")) {
                r = -ENOTTY;
                goto fail;
        }

        n_ifindices = sd_machine_get_ifindices(name, &ifindices);
        if (n_ifindices < 0) {
                r = n_ifindices;
                goto fail;
        }

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.machine1",
                               "/org/freedesktop/machine1",
                               "org.freedesktop.machine1.Manager",
                               "GetMachineAddresses",
                               NULL,
                               &reply,
                               "s", name);
        if (r < 0)
                goto fail;

        r = sd_bus_message_enter_container(reply, 'a', "(iay)");
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

                if (!IN_SET(family, AF_INET, AF_INET6)) {
                        r = -EAFNOSUPPORT;
                        goto fail;
                }

                if (sz != FAMILY_ADDRESS_SIZE(family)) {
                        r = -EINVAL;
                        goto fail;
                }

                r_tuple = (struct gaih_addrtuple*) (buffer + idx);
                r_tuple->next = i == c-1 ? NULL : (struct gaih_addrtuple*) ((char*) r_tuple + ALIGN(sizeof(struct gaih_addrtuple)));
                r_tuple->name = r_name;
                r_tuple->family = family;
                r_tuple->scopeid = n_ifindices == 1 ? ifindices[0] : 0;
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

enum nss_status _nss_mymachines_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

        _cleanup_bus_message_unref_ sd_bus_message* reply = NULL;
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        _cleanup_free_ char *class = NULL;
        unsigned c = 0, i = 0;
        char *r_name, *r_aliases, *r_addr, *r_addr_list;
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

        r = sd_machine_get_class(name, &class);
        if (r < 0)
                goto fail;
        if (!streq(class, "container")) {
                r = -ENOTTY;
                goto fail;
        }

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.machine1",
                               "/org/freedesktop/machine1",
                               "org.freedesktop.machine1.Manager",
                               "GetMachineAddresses",
                               NULL,
                               &reply,
                               "s", name);
        if (r < 0)
                goto fail;

        r = sd_bus_message_enter_container(reply, 'a', "(iay)");
        if (r < 0)
                goto fail;

        r = count_addresses(reply, af, &c);
        if (r < 0)
                goto fail;

        if (c <= 0) {
                *errnop = ENOENT;
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        alen = FAMILY_ADDRESS_SIZE(af);
        l = strlen(name);

        ms = ALIGN(l+1) + c * ALIGN(alen) + (c+2) * sizeof(char*);

        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = NO_RECOVERY;
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

NSS_GETHOSTBYNAME_FALLBACKS(mymachines)
