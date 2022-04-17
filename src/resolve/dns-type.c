/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <errno.h>

#include "dns-type.h"
#include "parse-util.h"
#include "string-util.h"

typedef const struct {
        uint16_t type;
        const char *name;
} dns_type;

static const struct dns_type_name *
lookup_dns_type (register const char *str, register GPERF_LEN_TYPE len);

#include "dns_type-from-name.h"
#include "dns_type-to-name.h"

int dns_type_from_string(const char *s) {
        const struct dns_type_name *sc;

        assert(s);

        sc = lookup_dns_type(s, strlen(s));
        if (sc)
                return sc->id;

        s = startswith_no_case(s, "TYPE");
        if (s) {
                unsigned x;

                if (safe_atou(s, &x) >= 0 &&
                    x <= UINT16_MAX)
                        return (int) x;
        }

        return _DNS_TYPE_INVALID;
}

bool dns_type_is_pseudo(uint16_t type) {

        /* Checks whether the specified type is a "pseudo-type". What
         * a "pseudo-type" precisely is, is defined only very weakly,
         * but apparently entails all RR types that are not actually
         * stored as RRs on the server and should hence also not be
         * cached. We use this list primarily to validate NSEC type
         * bitfields, and to verify what to cache. */

        return IN_SET(type,
                      0, /* A Pseudo RR type, according to RFC 2931 */
                      DNS_TYPE_ANY,
                      DNS_TYPE_AXFR,
                      DNS_TYPE_IXFR,
                      DNS_TYPE_OPT,
                      DNS_TYPE_TSIG,
                      DNS_TYPE_TKEY
        );
}

bool dns_class_is_pseudo(uint16_t class) {
        return class == DNS_CLASS_ANY;
}

bool dns_type_is_valid_query(uint16_t type) {

        /* The types valid as questions in packets */

        return !IN_SET(type,
                       0,
                       DNS_TYPE_OPT,
                       DNS_TYPE_TSIG,
                       DNS_TYPE_TKEY,

                       /* RRSIG are technically valid as questions, but we refuse doing explicit queries for them, as
                        * they aren't really payload, but signatures for payload, and cannot be validated on their
                        * own. After all they are the signatures, and have no signatures of their own validating
                        * them. */
                       DNS_TYPE_RRSIG);
}

bool dns_type_is_zone_transer(uint16_t type) {

        /* Zone transfers, either normal or incremental */

        return IN_SET(type,
                      DNS_TYPE_AXFR,
                      DNS_TYPE_IXFR);
}

bool dns_type_is_valid_rr(uint16_t type) {

        /* The types valid as RR in packets (but not necessarily
         * stored on servers). */

        return !IN_SET(type,
                       DNS_TYPE_ANY,
                       DNS_TYPE_AXFR,
                       DNS_TYPE_IXFR);
}

bool dns_class_is_valid_rr(uint16_t class) {
        return class != DNS_CLASS_ANY;
}

bool dns_type_may_redirect(uint16_t type) {
        /* The following record types should never be redirected using
         * CNAME/DNAME RRs. See
         * <https://tools.ietf.org/html/rfc4035#section-2.5>. */

        if (dns_type_is_pseudo(type))
                return false;

        return !IN_SET(type,
                       DNS_TYPE_CNAME,
                       DNS_TYPE_DNAME,
                       DNS_TYPE_NSEC3,
                       DNS_TYPE_NSEC,
                       DNS_TYPE_RRSIG,
                       DNS_TYPE_NXT,
                       DNS_TYPE_SIG,
                       DNS_TYPE_KEY);
}

bool dns_type_may_wildcard(uint16_t type) {

        /* The following records may not be expanded from wildcard RRsets */

        if (dns_type_is_pseudo(type))
                return false;

        return !IN_SET(type,
                       DNS_TYPE_NSEC3,
                       DNS_TYPE_SOA,

                       /* Prohibited by https://tools.ietf.org/html/rfc4592#section-4.4 */
                       DNS_TYPE_DNAME);
}

bool dns_type_apex_only(uint16_t type) {

        /* Returns true for all RR types that may only appear signed in a zone apex */

        return IN_SET(type,
                      DNS_TYPE_SOA,
                      DNS_TYPE_NS,            /* this one can appear elsewhere, too, but not signed */
                      DNS_TYPE_DNSKEY,
                      DNS_TYPE_NSEC3PARAM);
}

bool dns_type_is_dnssec(uint16_t type) {
        return IN_SET(type,
                      DNS_TYPE_DS,
                      DNS_TYPE_DNSKEY,
                      DNS_TYPE_RRSIG,
                      DNS_TYPE_NSEC,
                      DNS_TYPE_NSEC3,
                      DNS_TYPE_NSEC3PARAM);
}

bool dns_type_is_obsolete(uint16_t type) {
        return IN_SET(type,
                      /* Obsoleted by RFC 973 */
                      DNS_TYPE_MD,
                      DNS_TYPE_MF,
                      DNS_TYPE_MAILA,

                      /* Kinda obsoleted by RFC 2505 */
                      DNS_TYPE_MB,
                      DNS_TYPE_MG,
                      DNS_TYPE_MR,
                      DNS_TYPE_MINFO,
                      DNS_TYPE_MAILB,

                      /* RFC1127 kinda obsoleted this by recommending against its use */
                      DNS_TYPE_WKS,

                      /* Declared historical by RFC 6563 */
                      DNS_TYPE_A6,

                      /* Obsoleted by DNSSEC-bis */
                      DNS_TYPE_NXT,

                      /* RFC 1035 removed support for concepts that needed this from RFC 883 */
                      DNS_TYPE_NULL);
}

bool dns_type_needs_authentication(uint16_t type) {

        /* Returns true for all (non-obsolete) RR types where records are not useful if they aren't
         * authenticated. I.e. everything that contains crypto keys. */

        return IN_SET(type,
                      DNS_TYPE_CERT,
                      DNS_TYPE_SSHFP,
                      DNS_TYPE_IPSECKEY,
                      DNS_TYPE_DS,
                      DNS_TYPE_DNSKEY,
                      DNS_TYPE_TLSA,
                      DNS_TYPE_CDNSKEY,
                      DNS_TYPE_OPENPGPKEY,
                      DNS_TYPE_CAA);
}

int dns_type_to_af(uint16_t t) {
        switch (t) {

        case DNS_TYPE_A:
                return AF_INET;

        case DNS_TYPE_AAAA:
                return AF_INET6;

        case DNS_TYPE_ANY:
                return AF_UNSPEC;

        default:
                return -EINVAL;
        }
}

const char *dns_class_to_string(uint16_t class) {

        switch (class) {

        case DNS_CLASS_IN:
                return "IN";

        case DNS_CLASS_ANY:
                return "ANY";
        }

        return NULL;
}

int dns_class_from_string(const char *s) {

        if (!s)
                return _DNS_CLASS_INVALID;

        if (strcaseeq(s, "IN"))
                return DNS_CLASS_IN;
        else if (strcaseeq(s, "ANY"))
                return DNS_CLASS_ANY;

        return _DNS_CLASS_INVALID;
}

const char* tlsa_cert_usage_to_string(uint8_t cert_usage) {

        switch (cert_usage) {

        case 0:
                return "CA constraint";

        case 1:
                return "Service certificate constraint";

        case 2:
                return "Trust anchor assertion";

        case 3:
                return "Domain-issued certificate";

        case 4 ... 254:
                return "Unassigned";

        case 255:
                return "Private use";
        }

        return NULL;  /* clang cannot count that we covered everything */
}

const char* tlsa_selector_to_string(uint8_t selector) {
        switch (selector) {

        case 0:
                return "Full Certificate";

        case 1:
                return "SubjectPublicKeyInfo";

        case 2 ... 254:
                return "Unassigned";

        case 255:
                return "Private use";
        }

        return NULL;
}

const char* tlsa_matching_type_to_string(uint8_t selector) {

        switch (selector) {

        case 0:
                return "No hash used";

        case 1:
                return "SHA-256";

        case 2:
                return "SHA-512";

        case 3 ... 254:
                return "Unassigned";

        case 255:
                return "Private use";
        }

        return NULL;
}
