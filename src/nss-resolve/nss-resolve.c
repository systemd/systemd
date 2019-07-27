/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <netdb.h>
#include <nss.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-bus.h"

#include "bus-common-errors.h"
#include "errno-util.h"
#include "in-addr-util.h"
#include "macro.h"
#include "nss-util.h"
#include "resolved-def.h"
#include "signal-util.h"
#include "string-util.h"

NSS_GETHOSTBYNAME_PROTOTYPES(resolve);
NSS_GETHOSTBYADDR_PROTOTYPES(resolve);

static bool bus_error_shall_fallback(sd_bus_error *e) {
        return sd_bus_error_has_name(e, SD_BUS_ERROR_SERVICE_UNKNOWN) ||
               sd_bus_error_has_name(e, SD_BUS_ERROR_NAME_HAS_NO_OWNER) ||
               sd_bus_error_has_name(e, SD_BUS_ERROR_NO_REPLY) ||
               sd_bus_error_has_name(e, SD_BUS_ERROR_ACCESS_DENIED) ||
               sd_bus_error_has_name(e, SD_BUS_ERROR_DISCONNECTED) ||
               sd_bus_error_has_name(e, SD_BUS_ERROR_TIMEOUT);
}

static int count_addresses(sd_bus_message *m, int af, const char **canonical) {
        int c = 0, r;

        assert(m);
        assert(canonical);

        r = sd_bus_message_enter_container(m, 'a', "(iiay)");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_enter_container(m, 'r', "iiay")) > 0) {
                int family, ifindex;

                assert_cc(sizeof(int32_t) == sizeof(int));

                r = sd_bus_message_read(m, "ii", &ifindex, &family);
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

                c++;
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

static uint32_t ifindex_to_scopeid(int family, const void *a, int ifindex) {
        struct in6_addr in6;

        if (family != AF_INET6)
                return 0;

        /* Some apps can't deal with the scope ID attached to non-link-local addresses. Hence, let's suppress that. */

        assert(sizeof(in6) == FAMILY_ADDRESS_SIZE(AF_INET6));
        memcpy(&in6, a, sizeof(struct in6_addr));

        return IN6_IS_ADDR_LINKLOCAL(&in6) ? ifindex : 0;
}

static bool avoid_deadlock(void) {

        /* Check whether this lookup might have a chance of deadlocking because we are called from the service manager
         * code activating systemd-resolved.service. After all, we shouldn't synchronously do lookups to
         * systemd-resolved if we are required to finish before it can be started. This of course won't detect all
         * possible dead locks of this kind, but it should work for the most obvious cases. */

        if (geteuid() != 0) /* Ignore the env vars unless we are privileged. */
                return false;

        return streq_ptr(getenv("SYSTEMD_ACTIVATION_UNIT"), "systemd-resolved.service") &&
               streq_ptr(getenv("SYSTEMD_ACTIVATION_SCOPE"), "system");
}

enum nss_status _nss_resolve_gethostbyname4_r(
                const char *name,
                struct gaih_addrtuple **pat,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        struct gaih_addrtuple *r_tuple, *r_tuple_first = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *canonical = NULL;
        size_t l, ms, idx;
        char *r_name;
        int c, r, i = 0;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(name);
        assert(pat);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        if (avoid_deadlock()) {
                r = -EDEADLK;
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

        r = sd_bus_message_append(req, "isit", 0, name, AF_UNSPEC, (uint64_t) 0);
        if (r < 0)
                goto fail;

        r = sd_bus_call(bus, req, SD_RESOLVED_QUERY_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (!bus_error_shall_fallback(&error))
                        goto not_found;

                /* Return NSS_STATUS_UNAVAIL when communication with systemd-resolved fails,
                   allowing falling back to other nss modules. Treat all other error conditions as
                   NOTFOUND. This includes DNSSEC errors and suchlike. (We don't use UNAVAIL in this
                   case so that the nsswitch.conf configuration can distinguish such executed but
                   negative replies from complete failure to talk to resolved). */
                goto fail;
        }

        c = count_addresses(reply, AF_UNSPEC, &canonical);
        if (c < 0) {
                r = c;
                goto fail;
        }
        if (c == 0)
                goto not_found;

        if (isempty(canonical))
                canonical = name;

        l = strlen(canonical);
        ms = ALIGN(l+1) + ALIGN(sizeof(struct gaih_addrtuple)) * c;
        if (buflen < ms) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                *h_errnop = NETDB_INTERNAL;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, append name */
        r_name = buffer;
        memcpy(r_name, canonical, l+1);
        idx = ALIGN(l+1);

        /* Second, append addresses */
        r_tuple_first = (struct gaih_addrtuple*) (buffer + idx);

        r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
        if (r < 0)
                goto fail;

        while ((r = sd_bus_message_enter_container(reply, 'r', "iiay")) > 0) {
                int family, ifindex;
                const void *a;
                size_t sz;

                assert_cc(sizeof(int32_t) == sizeof(int));

                r = sd_bus_message_read(reply, "ii", &ifindex, &family);
                if (r < 0)
                        goto fail;

                if (ifindex < 0) {
                        r = -EINVAL;
                        goto fail;
                }

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
                r_tuple->scopeid = ifindex_to_scopeid(family, a, ifindex);
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

        /* Explicitly reset both *h_errnop and h_errno to work around
         * https://bugzilla.redhat.com/show_bug.cgi?id=1125975 */
        *h_errnop = NETDB_SUCCESS;
        h_errno = 0;

        return NSS_STATUS_SUCCESS;

fail:
        UNPROTECT_ERRNO;
        *errnop = -r;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;

not_found:
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_resolve_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        char *r_name, *r_aliases, *r_addr, *r_addr_list;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        size_t l, idx, ms, alen;
        const char *canonical;
        int c, r, i = 0;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(name);
        assert(result);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        if (af == AF_UNSPEC)
                af = AF_INET;

        if (!IN_SET(af, AF_INET, AF_INET6)) {
                r = -EAFNOSUPPORT;
                goto fail;
        }

        if (avoid_deadlock()) {
                r = -EDEADLK;
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

        r = sd_bus_call(bus, req, SD_RESOLVED_QUERY_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (!bus_error_shall_fallback(&error))
                        goto not_found;

                goto fail;
        }

        c = count_addresses(reply, af, &canonical);
        if (c < 0) {
                r = c;
                goto fail;
        }
        if (c == 0)
                goto not_found;

        if (isempty(canonical))
                canonical = name;

        alen = FAMILY_ADDRESS_SIZE(af);
        l = strlen(canonical);

        ms = ALIGN(l+1) + c * ALIGN(alen) + (c+2) * sizeof(char*);

        if (buflen < ms) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                *h_errnop = NETDB_INTERNAL;
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

        r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
        if (r < 0)
                goto fail;

        while ((r = sd_bus_message_enter_container(reply, 'r', "iiay")) > 0) {
                int ifindex, family;
                const void *a;
                size_t sz;

                r = sd_bus_message_read(reply, "ii", &ifindex, &family);
                if (r < 0)
                        goto fail;

                if (ifindex < 0) {
                        r = -EINVAL;
                        goto fail;
                }

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

        if (ttlp)
                *ttlp = 0;

        if (canonp)
                *canonp = r_name;

        /* Explicitly reset both *h_errnop and h_errno to work around
         * https://bugzilla.redhat.com/show_bug.cgi?id=1125975 */
        *h_errnop = NETDB_SUCCESS;
        h_errno = 0;

        return NSS_STATUS_SUCCESS;

fail:
        UNPROTECT_ERRNO;
        *errnop = -r;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;

not_found:
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_resolve_gethostbyaddr2_r(
                const void* addr, socklen_t len,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        char *r_name, *r_aliases, *r_addr, *r_addr_list;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        unsigned c = 0, i = 0;
        size_t ms = 0, idx;
        const char *n;
        int r, ifindex;

        PROTECT_ERRNO;
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);

        assert(addr);
        assert(result);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        if (!IN_SET(af, AF_INET, AF_INET6)) {
                UNPROTECT_ERRNO;
                *errnop = EAFNOSUPPORT;
                *h_errnop = NO_DATA;
                return NSS_STATUS_UNAVAIL;
        }

        if (len != FAMILY_ADDRESS_SIZE(af)) {
                r = -EINVAL;
                goto fail;
        }

        if (avoid_deadlock()) {
                r = -EDEADLK;
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

        r = sd_bus_call(bus, req, SD_RESOLVED_QUERY_TIMEOUT_USEC, &error, &reply);
        if (r < 0) {
                if (!bus_error_shall_fallback(&error))
                        goto not_found;

                goto fail;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(is)");
        if (r < 0)
                goto fail;

        while ((r = sd_bus_message_read(reply, "(is)", &ifindex, &n)) > 0) {

                if (ifindex < 0) {
                        r = -EINVAL;
                        goto fail;
                }

                c++;
                ms += ALIGN(strlen(n) + 1);
        }
        if (r < 0)
                goto fail;

        r = sd_bus_message_rewind(reply, false);
        if (r < 0)
                goto fail;

        if (c <= 0)
                goto not_found;

        ms += ALIGN(len) +              /* the address */
              2 * sizeof(char*) +       /* pointers to the address, plus trailing NULL */
              c * sizeof(char*);        /* pointers to aliases, plus trailing NULL */

        if (buflen < ms) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                *h_errnop = NETDB_INTERNAL;
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
        while ((r = sd_bus_message_read(reply, "(is)", &ifindex, &n)) > 0) {
                char *p;
                size_t l;

                l = strlen(n);
                p = buffer + idx;
                memcpy(p, n, l+1);

                if (i > 0)
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

        /* Explicitly reset both *h_errnop and h_errno to work around
         * https://bugzilla.redhat.com/show_bug.cgi?id=1125975 */
        *h_errnop = NETDB_SUCCESS;
        h_errno = 0;

        return NSS_STATUS_SUCCESS;

fail:
        UNPROTECT_ERRNO;
        *errnop = -r;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;

not_found:
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
}

NSS_GETHOSTBYNAME_FALLBACKS(resolve);
NSS_GETHOSTBYADDR_FALLBACKS(resolve);
