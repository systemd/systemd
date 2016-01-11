/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include "dns-type.h"
#include "string-util.h"

typedef const struct {
        uint16_t type;
        const char *name;
} dns_type;

static const struct dns_type_name *
lookup_dns_type (register const char *str, register unsigned int len);

#include "dns_type-from-name.h"
#include "dns_type-to-name.h"

int dns_type_from_string(const char *s) {
        const struct dns_type_name *sc;

        assert(s);

        sc = lookup_dns_type(s, strlen(s));
        if (!sc)
                return _DNS_TYPE_INVALID;

        return sc->id;
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
        return class == DNS_TYPE_ANY;
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
