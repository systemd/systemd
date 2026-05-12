/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netdb.h>
#include <nss.h>
#include <pthread.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "env-util.h"
#include "errno-util.h"
#include "glyph-util.h"
#include "in-addr-util.h"
#include "json-util.h"
#include "netlink-util.h"
#include "nss-util.h"
#include "ordered-set.h"
#include "resolve-varlink-util.h"
#include "resolved-def.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

NSS_GETHOSTBYNAME_PROTOTYPES(resolve);
NSS_GETHOSTBYADDR_PROTOTYPES(resolve);

static bool error_shall_fallback(const char *error_id) {
        /* The Varlink errors where we shall signal "please fallback" back to the NSS stack, so that some
         * fallback module can be loaded. (These are mostly all Varlink-internal errors, as apparently we
         * then were unable to even do IPC with systemd-resolved.) */
        return STR_IN_SET(error_id,
                          SD_VARLINK_ERROR_DISCONNECTED,
                          SD_VARLINK_ERROR_TIMEOUT,
                          SD_VARLINK_ERROR_PROTOCOL,
                          SD_VARLINK_ERROR_INTERFACE_NOT_FOUND,
                          SD_VARLINK_ERROR_METHOD_NOT_FOUND,
                          SD_VARLINK_ERROR_METHOD_NOT_IMPLEMENTED);
}

static bool error_shall_try_again(const char *error_id) {
        /* The Varlink errors where we shall signal "can't answer now but might be able to later" back to the
         * NSS stack. These are all errors that indicate lack of configuration or network problems. */
        return STR_IN_SET(error_id,
                          "io.systemd.Resolve.NoNameServers",
                          "io.systemd.Resolve.QueryTimedOut",
                          "io.systemd.Resolve.MaxAttemptsReached",
                          "io.systemd.Resolve.NetworkDown");
}

static int connect_to_resolved(sd_varlink **ret) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        int r;

        assert(ret);

        r = sd_varlink_connect_address(&link, "/run/systemd/resolve/io.systemd.Resolve");
        if (r < 0)
                return r;

        r = sd_varlink_set_relative_timeout(link, SD_RESOLVED_QUERY_TIMEOUT_USEC);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(link);
        return 0;
}

static uint64_t query_flag(
                const char *name,
                const int value,
                uint64_t flag) {

        int r;

        r = secure_getenv_bool(name);
        if (r >= 0)
                return r == value ? flag : 0;
        if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $%s, ignoring.", name);
        return 0;
}

static uint64_t query_flags(void) {
        /* Allow callers to turn off validation, synthetization, caching, etc., when we resolve via
         * nss-resolve. */
        return  query_flag("SYSTEMD_NSS_RESOLVE_VALIDATE", 0, SD_RESOLVED_NO_VALIDATE) |
                query_flag("SYSTEMD_NSS_RESOLVE_SYNTHESIZE", 0, SD_RESOLVED_NO_SYNTHESIZE) |
                query_flag("SYSTEMD_NSS_RESOLVE_CACHE", 0, SD_RESOLVED_NO_CACHE) |
                query_flag("SYSTEMD_NSS_RESOLVE_ZONE", 0, SD_RESOLVED_NO_ZONE) |
                query_flag("SYSTEMD_NSS_RESOLVE_TRUST_ANCHOR", 0, SD_RESOLVED_NO_TRUST_ANCHOR) |
                query_flag("SYSTEMD_NSS_RESOLVE_NETWORK", 0, SD_RESOLVED_NO_NETWORK);
}

static int query_ifindex(void) {
        int ifindex;
        const char *e;

        e = secure_getenv("SYSTEMD_NSS_RESOLVE_INTERFACE");
        if (!e)
                return 0;

        ifindex = rtnl_resolve_interface(/* rtnl= */ NULL, e);
        if (ifindex < 0) {
                log_debug_errno(ifindex, "Failed to resolve $SYSTEMD_NSS_RESOLVE_INTERFACE, ignoring: %m");
                ifindex = 0;
        }

        return ifindex;
}

enum nss_status _nss_resolve_gethostbyname4_r(
                const char *name,
                struct gaih_addrtuple **pat,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cparams = NULL;
        _cleanup_(resolve_hostname_reply_freep) ResolveHostnameReply *p = NULL;
        sd_json_variant *rparams;
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(name);
        assert(pat);
        assert(buffer);
        assert(errnop);
        assert(h_errnop);

        r = connect_to_resolved(&link);
        if (r < 0)
                goto fail;

        r = sd_json_buildo(
                        &cparams,
                        SD_JSON_BUILD_PAIR_STRING("name", name),
                        SD_JSON_BUILD_PAIR_UNSIGNED("flags", query_flags()),
                        SD_JSON_BUILD_PAIR_UNSIGNED("ifindex", query_ifindex()));
        if (r < 0)
                goto fail;

        /* Return NSS_STATUS_UNAVAIL when communication with systemd-resolved fails, allowing falling
         * back to other nss modules. Treat all other error conditions as NOTFOUND. This includes
         * DNSSEC errors and suchlike. (We don't use UNAVAIL in this case so that the nsswitch.conf
         * configuration can distinguish such executed but negative replies from complete failure to
         * talk to resolved). */
        const char *error_id;
        r = sd_varlink_call(link, "io.systemd.Resolve.ResolveHostname", cparams, &rparams, &error_id);
        if (r < 0)
                goto fail;
        if (!isempty(error_id)) {
                if (error_shall_try_again(error_id))
                        goto try_again;
                if (error_shall_fallback(error_id))
                        goto fail;
                if (streq(error_id, "io.systemd.Resolve.NoSuchResourceRecord"))
                        goto no_data;
                goto not_found;
        }

        r = dispatch_resolve_hostname_reply(NULL, rparams, nss_json_dispatch_flags, &p);
        if (r < 0)
                goto fail;
        if (ordered_set_isempty(p->addresses))
                goto not_found;

        size_t n_addresses = 0;
        ResolvedAddress *entry;
        ORDERED_SET_FOREACH(entry, p->addresses) {
                if (!IN_SET(entry->family, AF_INET, AF_INET6))
                        continue;

                n_addresses++;
        }

        const char *canonical = p->name ?: name;
        size_t l = strlen(canonical);
        size_t idx, ms = ALIGN(l+1) + ALIGN(sizeof(struct gaih_addrtuple)) * n_addresses;

        if (buflen < ms) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                *h_errnop = NETDB_INTERNAL;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, append name */
        char *r_name = buffer;
        memcpy(r_name, canonical, l + 1);
        idx = ALIGN(l + 1);

        /* Second, append addresses */
        struct gaih_addrtuple *r_tuple = NULL,
                *r_tuple_first = (struct gaih_addrtuple*) (buffer + idx);

        ORDERED_SET_FOREACH(entry, p->addresses) {
                if (!IN_SET(entry->family, AF_INET, AF_INET6))
                        continue;

                r_tuple = (struct gaih_addrtuple*) (buffer + idx);
                r_tuple->next = (struct gaih_addrtuple*) ((char*) r_tuple + ALIGN(sizeof(struct gaih_addrtuple)));
                r_tuple->name = r_name;
                r_tuple->family = entry->family;
                r_tuple->scopeid = entry->family == AF_INET6 && in6_addr_is_link_local(&entry->in_addr.in6) ? entry->ifindex : 0;
                memcpy(r_tuple->addr, entry->in_addr.bytes, FAMILY_ADDRESS_SIZE_SAFE(entry->family));

                idx += ALIGN(sizeof(struct gaih_addrtuple));
        }

        assert(r_tuple);  /* We had at least one address, so r_tuple must be set */
        r_tuple->next = NULL;  /* Override last next pointer */

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

no_data:
        *h_errnop = NO_DATA;
        return NSS_STATUS_NOTFOUND;

try_again:
        UNPROTECT_ERRNO;
        *errnop = -r;
        *h_errnop = TRY_AGAIN;
        return NSS_STATUS_TRYAGAIN;
}

enum nss_status _nss_resolve_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cparams = NULL;
        _cleanup_(resolve_hostname_reply_freep) ResolveHostnameReply *p = NULL;
        sd_json_variant *rparams;
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

        if (!IN_SET(af, AF_INET, AF_INET6)) {
                r = -EAFNOSUPPORT;
                goto fail;
        }

        r = connect_to_resolved(&link);
        if (r < 0)
                goto fail;

        r = sd_json_buildo(
                        &cparams,
                        SD_JSON_BUILD_PAIR_STRING("name", name),
                        SD_JSON_BUILD_PAIR_INTEGER("family", af),
                        SD_JSON_BUILD_PAIR_UNSIGNED("flags", query_flags()),
                        SD_JSON_BUILD_PAIR_UNSIGNED("ifindex", query_ifindex()));
        if (r < 0)
                goto fail;

        const char *error_id;
        r = sd_varlink_call(link, "io.systemd.Resolve.ResolveHostname", cparams, &rparams, &error_id);
        if (r < 0)
                goto fail;
        if (!isempty(error_id)) {
                if (error_shall_try_again(error_id))
                        goto try_again;
                if (error_shall_fallback(error_id))
                        goto fail;
                if (streq(error_id, "io.systemd.Resolve.NoSuchResourceRecord"))
                        goto no_data;
                goto not_found;
        }

        r = dispatch_resolve_hostname_reply(NULL, rparams, nss_json_dispatch_flags, &p);
        if (r < 0)
                goto fail;
        if (ordered_set_isempty(p->addresses))
                goto not_found;

        size_t n_addresses = 0;
        ResolvedAddress *entry;
        ORDERED_SET_FOREACH(entry, p->addresses) {
                if (entry->family != af)
                        continue;

                n_addresses++;
        }

        const char *canonical = p->name ?: name;

        size_t alen = FAMILY_ADDRESS_SIZE(af);
        size_t l = strlen(canonical);

        size_t idx, ms = ALIGN(l + 1) + n_addresses * ALIGN(alen) + (n_addresses + 2) * sizeof(char*);

        if (buflen < ms) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                *h_errnop = NETDB_INTERNAL;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, append name */
        char *r_name = buffer;
        memcpy(r_name, canonical, l+1);
        idx = ALIGN(l+1);

        /* Second, create empty aliases array */
        char *r_aliases = buffer + idx;
        ((char**) r_aliases)[0] = NULL;
        idx += sizeof(char*);

        /* Third, append addresses */
        char *r_addr = buffer + idx;

        size_t i = 0;
        ORDERED_SET_FOREACH(entry, p->addresses) {
                if (entry->family != af)
                        continue;

                if (FAMILY_ADDRESS_SIZE_SAFE(entry->family) != alen) {
                        r = -EINVAL;
                        goto fail;
                }

                memcpy(r_addr + i*ALIGN(alen), entry->in_addr.bytes, alen);
                i++;
        }

        assert(i == n_addresses);
        idx += n_addresses * ALIGN(alen);

        /* Fourth, append address pointer array */
        char *r_addr_list = buffer + idx;
        for (i = 0; i < n_addresses; i++)
                ((char**) r_addr_list)[i] = r_addr + i*ALIGN(alen);

        ((char**) r_addr_list)[i] = NULL;
        idx += (n_addresses + 1) * sizeof(char*);

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

no_data:
        *h_errnop = NO_DATA;
        return NSS_STATUS_NOTFOUND;

try_again:
        UNPROTECT_ERRNO;
        *errnop = -r;
        *h_errnop = TRY_AGAIN;
        return NSS_STATUS_TRYAGAIN;
}

enum nss_status _nss_resolve_gethostbyaddr2_r(
                const void* addr, socklen_t len,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cparams = NULL;
        _cleanup_(resolve_address_reply_freep) ResolveAddressReply *p = NULL;
        sd_json_variant *rparams;
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

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

        r = connect_to_resolved(&link);
        if (r < 0)
                goto fail;

        r = sd_json_buildo(
                        &cparams,
                        SD_JSON_BUILD_PAIR_BYTE_ARRAY("address", addr, len),
                        SD_JSON_BUILD_PAIR_INTEGER("family", af),
                        SD_JSON_BUILD_PAIR_UNSIGNED("flags", query_flags()),
                        SD_JSON_BUILD_PAIR_UNSIGNED("ifindex", query_ifindex()));
        if (r < 0)
                goto fail;

        const char* error_id;
        r = sd_varlink_call(link, "io.systemd.Resolve.ResolveAddress", cparams, &rparams, &error_id);
        if (r < 0)
                goto fail;
        if (!isempty(error_id)) {
                if (error_shall_try_again(error_id))
                        goto try_again;
                if (error_shall_fallback(error_id))
                        goto fail;
                goto not_found;
        }

        r = dispatch_resolve_address_reply(NULL, rparams, nss_json_dispatch_flags, &p);
        if (r < 0)
                goto fail;
        if (ordered_set_isempty(p->names))
                goto not_found;

        size_t ms = 0, idx;

        ResolvedName *entry;
        ORDERED_SET_FOREACH(entry, p->names)
                ms += ALIGN(strlen(entry->name) + 1);

        size_t n_names = ordered_set_size(p->names);
        ms += ALIGN(len) +                    /* the address */
              2 * sizeof(char*) +             /* pointer to the address, plus trailing NULL */
              n_names * sizeof(char*);        /* pointers to aliases, plus trailing NULL */

        if (buflen < ms) {
                UNPROTECT_ERRNO;
                *errnop = ERANGE;
                *h_errnop = NETDB_INTERNAL;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, place address */
        char *r_addr = buffer;
        memcpy(r_addr, addr, len);
        idx = ALIGN(len);

        /* Second, place address list */
        char *r_addr_list = buffer + idx;
        ((char**) r_addr_list)[0] = r_addr;
        ((char**) r_addr_list)[1] = NULL;
        idx += sizeof(char*) * 2;

        /* Third, reserve space for the aliases array, plus trailing NULL */
        char *r_aliases = buffer + idx;
        idx += sizeof(char*) * n_names;

        /* Fourth, place aliases */
        char *r_name = buffer + idx;

        size_t i = 0;
        ORDERED_SET_FOREACH(entry, p->names) {
                size_t l = strlen(entry->name);
                char *z = buffer + idx;
                memcpy(z, entry->name, l + 1);

                if (i > 0)
                        ((char**) r_aliases)[i - 1] = z;
                i++;

                idx += ALIGN(l + 1);
        }
        ((char**) r_aliases)[n_names - 1] = NULL;

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

try_again:
        UNPROTECT_ERRNO;
        *errnop = -r;
        *h_errnop = TRY_AGAIN;
        return NSS_STATUS_TRYAGAIN;
}

NSS_GETHOSTBYNAME_FALLBACKS(resolve);
NSS_GETHOSTBYADDR_FALLBACKS(resolve);
