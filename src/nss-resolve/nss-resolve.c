/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <netdb.h>
#include <nss.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "env-util.h"
#include "errno-util.h"
#include "glyph-util.h"
#include "in-addr-util.h"
#include "macro.h"
#include "nss-util.h"
#include "resolved-def.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "varlink.h"

static JsonDispatchFlags json_dispatch_flags = 0;

static void setup_logging(void) {
        log_parse_environment_variables();

        if (DEBUG_LOGGING)
                json_dispatch_flags = JSON_LOG;
}

static void setup_logging_once(void) {
        static pthread_once_t once = PTHREAD_ONCE_INIT;
        assert_se(pthread_once(&once, setup_logging) == 0);
}

#define NSS_ENTRYPOINT_BEGIN                    \
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);       \
        setup_logging_once()

NSS_GETHOSTBYNAME_PROTOTYPES(resolve);
NSS_GETHOSTBYADDR_PROTOTYPES(resolve);

static bool error_shall_fallback(const char *error_id) {
        /* The Varlink errors where we shall signal "please fallback" back to the NSS stack, so that some
         * fallback module can be loaded. (These are mostly all Varlink-internal errors, as apparently we
         * then were unable to even do IPC with systemd-resolved.) */
        return STR_IN_SET(error_id,
                          VARLINK_ERROR_DISCONNECTED,
                          VARLINK_ERROR_TIMEOUT,
                          VARLINK_ERROR_PROTOCOL,
                          VARLINK_ERROR_INTERFACE_NOT_FOUND,
                          VARLINK_ERROR_METHOD_NOT_FOUND,
                          VARLINK_ERROR_METHOD_NOT_IMPLEMENTED);
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

static int connect_to_resolved(Varlink **ret) {
        _cleanup_(varlink_unrefp) Varlink *link = NULL;
        int r;

        r = varlink_connect_address(&link, "/run/systemd/resolve/io.systemd.Resolve");
        if (r < 0)
                return r;

        r = varlink_set_relative_timeout(link, SD_RESOLVED_QUERY_TIMEOUT_USEC);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(link);
        return 0;
}

static uint32_t ifindex_to_scopeid(int family, const void *a, int ifindex) {
        struct in6_addr in6;

        if (family != AF_INET6 || ifindex == 0)
                return 0;

        /* Some apps can't deal with the scope ID attached to non-link-local addresses. Hence, let's suppress that. */

        assert(sizeof(in6) == FAMILY_ADDRESS_SIZE(AF_INET6));
        memcpy(&in6, a, sizeof(struct in6_addr));

        return in6_addr_is_link_local(&in6) ? ifindex : 0;
}

static int json_dispatch_ifindex(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        int *ifi = ASSERT_PTR(userdata);
        int64_t t;

        assert(variant);

        if (!json_variant_is_integer(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        t = json_variant_integer(variant);
        if (t > INT_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is out of bounds for an interface index.", strna(name));

        *ifi = (int) t;
        return 0;
}

static int json_dispatch_family(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        int *family = ASSERT_PTR(userdata);
        int64_t t;

        assert(variant);

        if (!json_variant_is_integer(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        t = json_variant_integer(variant);
        if (t < 0 || t > INT_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid family.", strna(name));

        *family = (int) t;
        return 0;
}

typedef struct ResolveHostnameReply {
        JsonVariant *addresses;
        char *name;
        uint64_t flags;
} ResolveHostnameReply;

static void resolve_hostname_reply_destroy(ResolveHostnameReply *p) {
        assert(p);

        json_variant_unref(p->addresses);
        free(p->name);
}

static const JsonDispatch resolve_hostname_reply_dispatch_table[] = {
        { "addresses", JSON_VARIANT_ARRAY,    json_dispatch_variant, offsetof(ResolveHostnameReply, addresses), JSON_MANDATORY },
        { "name",      JSON_VARIANT_STRING,   json_dispatch_string,  offsetof(ResolveHostnameReply, name),      0              },
        { "flags",     JSON_VARIANT_UNSIGNED, json_dispatch_uint64,  offsetof(ResolveHostnameReply, flags),     0              },
        {}
};

typedef struct AddressParameters {
        int ifindex;
        int family;
        union in_addr_union address;
        size_t address_size;
} AddressParameters;

static int json_dispatch_address(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        AddressParameters *p = ASSERT_PTR(userdata);
        union in_addr_union buf = {};
        JsonVariant *i;
        size_t n, k = 0;

        assert(variant);

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        n = json_variant_elements(variant);
        if (!IN_SET(n, 4, 16))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is array of unexpected size.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                int64_t b;

                if (!json_variant_is_integer(i))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Element %zu of JSON field '%s' is not an integer.", k, strna(name));

                b = json_variant_integer(i);
                if (b < 0 || b > 0xff)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Element %zu of JSON field '%s' is out of range 0%s255.",
                                        k, strna(name), special_glyph(SPECIAL_GLYPH_ELLIPSIS));

                buf.bytes[k++] = (uint8_t) b;
        }

        p->address = buf;
        p->address_size = k;

        return 0;
}

static const JsonDispatch address_parameters_dispatch_table[] = {
        { "ifindex", JSON_VARIANT_INTEGER,  json_dispatch_ifindex, offsetof(AddressParameters, ifindex), 0              },
        { "family",  JSON_VARIANT_INTEGER,  json_dispatch_family,  offsetof(AddressParameters, family),  JSON_MANDATORY },
        { "address", JSON_VARIANT_ARRAY,    json_dispatch_address, 0,                                    JSON_MANDATORY },
        {}
};

static uint64_t query_flag(
                const char *name,
                const int value,
                uint64_t flag) {
        int r;

        r = getenv_bool_secure(name);
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

enum nss_status _nss_resolve_gethostbyname4_r(
                const char *name,
                struct gaih_addrtuple **pat,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        _cleanup_(varlink_unrefp) Varlink *link = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *cparams = NULL;
        _cleanup_(resolve_hostname_reply_destroy) ResolveHostnameReply p = {};
        JsonVariant *rparams, *entry;
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

        r = json_build(&cparams, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("name", JSON_BUILD_STRING(name)),
                                       JSON_BUILD_PAIR("flags", JSON_BUILD_UNSIGNED(query_flags()))));
        if (r < 0)
                goto fail;

        /* Return NSS_STATUS_UNAVAIL when communication with systemd-resolved fails, allowing falling
         * back to other nss modules. Treat all other error conditions as NOTFOUND. This includes
         * DNSSEC errors and suchlike. (We don't use UNAVAIL in this case so that the nsswitch.conf
         * configuration can distinguish such executed but negative replies from complete failure to
         * talk to resolved). */
        const char *error_id;
        r = varlink_call(link, "io.systemd.Resolve.ResolveHostname", cparams, &rparams, &error_id, NULL);
        if (r < 0)
                goto fail;
        if (!isempty(error_id)) {
                if (error_shall_try_again(error_id))
                        goto try_again;
                if (error_shall_fallback(error_id))
                        goto fail;
                goto not_found;
        }

        r = json_dispatch(rparams, resolve_hostname_reply_dispatch_table, NULL, json_dispatch_flags, &p);
        if (r < 0)
                goto fail;
        if (json_variant_is_blank_object(p.addresses))
                goto not_found;

        size_t n_addresses = 0;
        JSON_VARIANT_ARRAY_FOREACH(entry, p.addresses) {
                AddressParameters q = {};

                r = json_dispatch(entry, address_parameters_dispatch_table, NULL, json_dispatch_flags, &q);
                if (r < 0)
                        goto fail;

                if (!IN_SET(q.family, AF_INET, AF_INET6))
                        continue;

                if (q.address_size != FAMILY_ADDRESS_SIZE(q.family)) {
                        r = -EINVAL;
                        goto fail;
                }

                n_addresses++;
        }

        const char *canonical = p.name ?: name;
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

        JSON_VARIANT_ARRAY_FOREACH(entry, p.addresses) {
                AddressParameters q = {};

                r = json_dispatch(entry, address_parameters_dispatch_table, NULL, json_dispatch_flags, &q);
                if (r < 0)
                        goto fail;

                if (!IN_SET(q.family, AF_INET, AF_INET6))
                        continue;

                r_tuple = (struct gaih_addrtuple*) (buffer + idx);
                r_tuple->next = (struct gaih_addrtuple*) ((char*) r_tuple + ALIGN(sizeof(struct gaih_addrtuple)));
                r_tuple->name = r_name;
                r_tuple->family = q.family;
                r_tuple->scopeid = ifindex_to_scopeid(q.family, &q.address, q.ifindex);
                memcpy(r_tuple->addr, &q.address, q.address_size);

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

        _cleanup_(varlink_unrefp) Varlink *link = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *cparams = NULL;
        _cleanup_(resolve_hostname_reply_destroy) ResolveHostnameReply p = {};
        JsonVariant *rparams, *entry;
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

        r = json_build(&cparams, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("name", JSON_BUILD_STRING(name)),
                                                   JSON_BUILD_PAIR("family", JSON_BUILD_INTEGER(af)),
                                                   JSON_BUILD_PAIR("flags", JSON_BUILD_UNSIGNED(query_flags()))));
        if (r < 0)
                goto fail;

        const char *error_id;
        r = varlink_call(link, "io.systemd.Resolve.ResolveHostname", cparams, &rparams, &error_id, NULL);
        if (r < 0)
                goto fail;
        if (!isempty(error_id)) {
                if (error_shall_try_again(error_id))
                        goto try_again;
                if (error_shall_fallback(error_id))
                        goto fail;
                goto not_found;
        }

        r = json_dispatch(rparams, resolve_hostname_reply_dispatch_table, NULL, json_dispatch_flags, &p);
        if (r < 0)
                goto fail;
        if (json_variant_is_blank_object(p.addresses))
                goto not_found;

        size_t n_addresses = 0;
        JSON_VARIANT_ARRAY_FOREACH(entry, p.addresses) {
                AddressParameters q = {};

                r = json_dispatch(entry, address_parameters_dispatch_table, NULL, json_dispatch_flags, &q);
                if (r < 0)
                        goto fail;

                if (!IN_SET(q.family, AF_INET, AF_INET6))
                        continue;

                if (q.address_size != FAMILY_ADDRESS_SIZE(q.family)) {
                        r = -EINVAL;
                        goto fail;
                }

                n_addresses++;
        }

        const char *canonical = p.name ?: name;

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
        JSON_VARIANT_ARRAY_FOREACH(entry, p.addresses) {
                AddressParameters q = {};

                r = json_dispatch(entry, address_parameters_dispatch_table, NULL, json_dispatch_flags, &q);
                if (r < 0)
                        goto fail;

                if (q.family != af)
                        continue;

                if (q.address_size != alen) {
                        r = -EINVAL;
                        goto fail;
                }

                memcpy(r_addr + i*ALIGN(alen), &q.address, alen);
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

try_again:
        UNPROTECT_ERRNO;
        *errnop = -r;
        *h_errnop = TRY_AGAIN;
        return NSS_STATUS_TRYAGAIN;
}

typedef struct ResolveAddressReply {
        JsonVariant *names;
        uint64_t flags;
} ResolveAddressReply;

static void resolve_address_reply_destroy(ResolveAddressReply *p) {
        assert(p);

        json_variant_unref(p->names);
}

static const JsonDispatch resolve_address_reply_dispatch_table[] = {
        { "names", JSON_VARIANT_ARRAY,    json_dispatch_variant, offsetof(ResolveAddressReply, names), JSON_MANDATORY },
        { "flags", JSON_VARIANT_UNSIGNED, json_dispatch_uint64,  offsetof(ResolveAddressReply, flags), 0              },
        {}
};

typedef struct NameParameters {
        int ifindex;
        char *name;
} NameParameters;

static void name_parameters_destroy(NameParameters *p) {
        assert(p);

        free(p->name);
}

static const JsonDispatch name_parameters_dispatch_table[] = {
        { "ifindex", JSON_VARIANT_INTEGER, json_dispatch_ifindex, offsetof(NameParameters, ifindex), 0              },
        { "name",    JSON_VARIANT_STRING,  json_dispatch_string,  offsetof(NameParameters, name),    JSON_MANDATORY },
        {}
};

enum nss_status _nss_resolve_gethostbyaddr2_r(
                const void* addr, socklen_t len,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp) {

        _cleanup_(varlink_unrefp) Varlink *link = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *cparams = NULL;
        _cleanup_(resolve_address_reply_destroy) ResolveAddressReply p = {};
        JsonVariant *rparams, *entry;
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

        r = json_build(&cparams, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("address", JSON_BUILD_BYTE_ARRAY(addr, len)),
                                                   JSON_BUILD_PAIR("family", JSON_BUILD_INTEGER(af)),
                                                   JSON_BUILD_PAIR("flags", JSON_BUILD_UNSIGNED(query_flags()))));
        if (r < 0)
                goto fail;

        const char* error_id;
        r = varlink_call(link, "io.systemd.Resolve.ResolveAddress", cparams, &rparams, &error_id, NULL);
        if (r < 0)
                goto fail;
        if (!isempty(error_id)) {
                if (error_shall_try_again(error_id))
                        goto try_again;
                if (error_shall_fallback(error_id))
                        goto fail;
                goto not_found;
        }

        r = json_dispatch(rparams, resolve_address_reply_dispatch_table, NULL, json_dispatch_flags, &p);
        if (r < 0)
                goto fail;
        if (json_variant_is_blank_object(p.names))
                goto not_found;

        size_t ms = 0, idx;

        JSON_VARIANT_ARRAY_FOREACH(entry, p.names) {
                _cleanup_(name_parameters_destroy) NameParameters q = {};

                r = json_dispatch(entry, name_parameters_dispatch_table, NULL, json_dispatch_flags, &q);
                if (r < 0)
                        goto fail;

                ms += ALIGN(strlen(q.name) + 1);
        }

        size_t n_names = json_variant_elements(p.names);
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
        JSON_VARIANT_ARRAY_FOREACH(entry, p.names) {
                _cleanup_(name_parameters_destroy) NameParameters q = {};

                r = json_dispatch(entry, name_parameters_dispatch_table, NULL, json_dispatch_flags, &q);
                if (r < 0)
                        goto fail;

                size_t l = strlen(q.name);
                char *z = buffer + idx;
                memcpy(z, q.name, l + 1);

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
