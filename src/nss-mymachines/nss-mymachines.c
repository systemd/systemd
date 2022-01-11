/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netdb.h>
#include <nss.h>
#include <pthread.h>

#include "sd-bus.h"
#include "sd-login.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-locator.h"
#include "env-util.h"
#include "errno-util.h"
#include "format-util.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "nss-util.h"
#include "signal-util.h"
#include "string-util.h"

static void setup_logging_once(void) {
        static pthread_once_t once = PTHREAD_ONCE_INIT;
        assert_se(pthread_once(&once, log_parse_environment_variables) == 0);
}

#define NSS_ENTRYPOINT_BEGIN                    \
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);       \
        setup_logging_once()

NSS_GETHOSTBYNAME_PROTOTYPES(mymachines);
NSS_GETPW_PROTOTYPES(mymachines);
NSS_GETGR_PROTOTYPES(mymachines);

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

                c++;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_rewind(m, false);
        if (r < 0)
                return r;

        *ret = c;
        return 0;
}

static bool avoid_deadlock(void) {

        /* Check whether this lookup might have a chance of deadlocking because we are called from the service manager
         * code activating systemd-machined.service. After all, we shouldn't synchronously do lookups to
         * systemd-machined if we are required to finish before it can be started. This of course won't detect all
         * possible dead locks of this kind, but it should work for the most obvious cases. */

        if (geteuid() != 0) /* Ignore the env vars unless we are privileged. */
                return false;

        return streq_ptr(getenv("SYSTEMD_ACTIVATION_UNIT"), "systemd-machined.service") &&
               streq_ptr(getenv("SYSTEMD_ACTIVATION_SCOPE"), "system");
}

enum nss_status _nss_mymachines_gethostbyname4_r(
                const char *name,
                struct gaih_addrtuple **pat,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        struct gaih_addrtuple *r_tuple, *r_tuple_first = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message* reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ int *ifindices = NULL;
        _cleanup_free_ char *class = NULL;
        size_t l, ms, idx;
        unsigned i = 0, c = 0;
        char *r_name;
        int n_ifindices, r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

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

        if (avoid_deadlock()) {
                r = -EDEADLK;
                goto fail;
        }

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = bus_call_method(bus, bus_machine_mgr, "GetMachineAddresses", NULL, &reply, "s", name);
        if (r < 0)
                goto fail;

        r = sd_bus_message_enter_container(reply, 'a', "(iay)");
        if (r < 0)
                goto fail;

        r = count_addresses(reply, AF_UNSPEC, &c);
        if (r < 0)
                goto fail;

        if (c <= 0) {
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        l = strlen(name);
        ms = ALIGN(l+1) + ALIGN(sizeof(struct gaih_addrtuple)) * c;
        if (buflen < ms) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                *h_errnop = NETDB_INTERNAL;
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
}

enum nss_status _nss_mymachines_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message* reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *class = NULL;
        unsigned c = 0, i = 0;
        char *r_name, *r_aliases, *r_addr, *r_addr_list;
        size_t l, idx, ms, alen;
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

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

        if (avoid_deadlock()) {
                r = -EDEADLK;
                goto fail;
        }

        r = sd_bus_open_system(&bus);
        if (r < 0)
                goto fail;

        r = bus_call_method(bus, bus_machine_mgr, "GetMachineAddresses", NULL, &reply, "s", name);
        if (r < 0)
                goto fail;

        r = sd_bus_message_enter_container(reply, 'a', "(iay)");
        if (r < 0)
                goto fail;

        r = count_addresses(reply, af, &c);
        if (r < 0)
                goto fail;

        if (c <= 0) {
                *h_errnop = HOST_NOT_FOUND;
                return NSS_STATUS_NOTFOUND;
        }

        alen = FAMILY_ADDRESS_SIZE(af);
        l = strlen(name);

        ms = ALIGN(l+1) + c * ALIGN(alen) + (c+2) * sizeof(char*);

        if (buflen < ms) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                *h_errnop = NETDB_INTERNAL;
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
}

NSS_GETHOSTBYNAME_FALLBACKS(mymachines);

enum nss_status _nss_mymachines_getpwnam_r(
                const char *name,
                struct passwd *pwd,
                char *buffer, size_t buflen,
                int *errnop) {

        return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_mymachines_getpwuid_r(
                uid_t uid,
                struct passwd *pwd,
                char *buffer, size_t buflen,
                int *errnop) {

        return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_mymachines_getgrnam_r(
                const char *name,
                struct group *gr,
                char *buffer, size_t buflen,
                int *errnop) {

        return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_mymachines_getgrgid_r(
                gid_t gid,
                struct group *gr,
                char *buffer, size_t buflen,
                int *errnop) {

        return NSS_STATUS_NOTFOUND;
}
