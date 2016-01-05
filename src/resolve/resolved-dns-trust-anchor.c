/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <sd-messages.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "def.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "parse-util.h"
#include "resolved-dns-trust-anchor.h"
#include "resolved-dns-dnssec.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"

static const char trust_anchor_dirs[] = CONF_PATHS_NULSTR("dnssec-trust-anchors.d");

/* The DS RR from https://data.iana.org/root-anchors/root-anchors.xml, retrieved December 2015 */
static const uint8_t root_digest[] =
        { 0x49, 0xAA, 0xC1, 0x1D, 0x7B, 0x6F, 0x64, 0x46, 0x70, 0x2E, 0x54, 0xA1, 0x60, 0x73, 0x71, 0x60,
          0x7A, 0x1A, 0x41, 0x85, 0x52, 0x00, 0xFD, 0x2C, 0xE1, 0xCD, 0xDE, 0x32, 0xF2, 0x4E, 0x8F, 0xB5 };

static int dns_trust_anchor_add_builtin(DnsTrustAnchor *d) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        int r;

        assert(d);

        r = hashmap_ensure_allocated(&d->positive_by_key, &dns_resource_key_hash_ops);
        if (r < 0)
                return r;

        if (hashmap_get(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_DS, ".")))
                return 0;

        if (hashmap_get(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_DNSKEY, ".")))
                return 0;

        /* Add the RR from https://data.iana.org/root-anchors/root-anchors.xml */
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DS, "");
        if (!rr)
                return -ENOMEM;

        rr->ds.key_tag = 19036;
        rr->ds.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        rr->ds.digest_type = DNSSEC_DIGEST_SHA256;
        rr->ds.digest_size = sizeof(root_digest);
        rr->ds.digest = memdup(root_digest, rr->ds.digest_size);
        if (!rr->ds.digest)
                return  -ENOMEM;

        answer = dns_answer_new(1);
        if (!answer)
                return -ENOMEM;

        r = dns_answer_add(answer, rr, 0, DNS_ANSWER_AUTHENTICATED);
        if (r < 0)
                return r;

        r = hashmap_put(d->positive_by_key, rr->key, answer);
        if (r < 0)
                return r;

        answer = NULL;
        return 0;
}

static int dns_trust_anchor_load_positive(DnsTrustAnchor *d, const char *path, unsigned line, const char *s) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_free_ char *domain = NULL, *class = NULL, *type = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsAnswer *old_answer = NULL;
        const char *p = s;
        int r;

        assert(d);
        assert(line);

        r = extract_first_word(&p, &domain, NULL, EXTRACT_QUOTES);
        if (r < 0)
                return log_warning_errno(r, "Unable to parse domain in line %s:%u: %m", path, line);

        if (!dns_name_is_valid(domain)) {
                log_warning("Domain name %s is invalid, at line %s:%u, ignoring line.", domain, path, line);
                return -EINVAL;
        }

        r = extract_many_words(&p, NULL, 0, &class, &type, NULL);
        if (r < 0)
                return log_warning_errno(r, "Unable to parse class and type in line %s:%u: %m", path, line);
        if (r != 2) {
                log_warning("Missing class or type in line %s:%u", path, line);
                return -EINVAL;
        }

        if (!strcaseeq(class, "IN")) {
                log_warning("RR class %s is not supported, ignoring line %s:%u.", class, path, line);
                return -EINVAL;
        }

        if (strcaseeq(type, "DS")) {
                _cleanup_free_ char *key_tag = NULL, *algorithm = NULL, *digest_type = NULL, *digest = NULL;
                _cleanup_free_ void *dd = NULL;
                uint16_t kt;
                int a, dt;
                size_t l;

                r = extract_many_words(&p, NULL, 0, &key_tag, &algorithm, &digest_type, &digest, NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse DS parameters on line %s:%u: %m", path, line);
                        return -EINVAL;
                }
                if (r != 4) {
                        log_warning("Missing DS parameters on line %s:%u", path, line);
                        return -EINVAL;
                }

                r = safe_atou16(key_tag, &kt);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse DS key tag %s on line %s:%u: %m", key_tag, path, line);

                a = dnssec_algorithm_from_string(algorithm);
                if (a < 0) {
                        log_warning("Failed to parse DS algorithm %s on line %s:%u", algorithm, path, line);
                        return -EINVAL;
                }

                dt = dnssec_digest_from_string(digest_type);
                if (dt < 0) {
                        log_warning("Failed to parse DS digest type %s on line %s:%u", digest_type, path, line);
                        return -EINVAL;
                }

                r = unhexmem(digest, strlen(digest), &dd, &l);
                if (r < 0) {
                        log_warning("Failed to parse DS digest %s on line %s:%u", digest, path, line);
                        return -EINVAL;
                }

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DS, domain);
                if (!rr)
                        return log_oom();

                rr->ds.key_tag = kt;
                rr->ds.algorithm = a;
                rr->ds.digest_type = dt;
                rr->ds.digest_size = l;
                rr->ds.digest = dd;
                dd = NULL;

        } else if (strcaseeq(type, "DNSKEY")) {
                _cleanup_free_ char *flags = NULL, *protocol = NULL, *algorithm = NULL, *key = NULL;
                _cleanup_free_ void *k = NULL;
                uint16_t f;
                size_t l;
                int a;

                r = extract_many_words(&p, NULL, 0, &flags, &protocol, &algorithm, &key, NULL);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse DNSKEY parameters on line %s:%u: %m", path, line);
                if (r != 4) {
                        log_warning("Missing DNSKEY parameters on line %s:%u", path, line);
                        return -EINVAL;
                }

                if (!streq(protocol, "3")) {
                        log_warning("DNSKEY Protocol is not 3 on line %s:%u", path, line);
                        return -EINVAL;
                }

                r = safe_atou16(flags, &f);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse DNSKEY flags field %s on line %s:%u", flags, path, line);
                if ((f & DNSKEY_FLAG_ZONE_KEY) == 0) {
                        log_warning("DNSKEY lacks zone key bit set on line %s:%u", path, line);
                        return -EINVAL;
                }
                if ((f & DNSKEY_FLAG_REVOKE)) {
                        log_warning("DNSKEY is already revoked on line %s:%u", path, line);
                        return -EINVAL;
                }

                a = dnssec_algorithm_from_string(algorithm);
                if (a < 0) {
                        log_warning("Failed to parse DNSKEY algorithm %s on line %s:%u", algorithm, path, line);
                        return -EINVAL;
                }

                r = unbase64mem(key, strlen(key), &k, &l);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse DNSKEY key data %s on line %s:%u", key, path, line);

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNSKEY, domain);
                if (!rr)
                        return log_oom();

                rr->dnskey.flags = f;
                rr->dnskey.protocol = 3;
                rr->dnskey.algorithm = a;
                rr->dnskey.key_size = l;
                rr->dnskey.key = k;
                k = NULL;

        } else {
                log_warning("RR type %s is not supported, ignoring line %s:%u.", type, path, line);
                return -EINVAL;
        }

        if (!isempty(p)) {
                log_warning("Trailing garbage on line %s:%u, ignoring line.", path, line);
                return -EINVAL;
        }

        r = hashmap_ensure_allocated(&d->positive_by_key, &dns_resource_key_hash_ops);
        if (r < 0)
                return r;

        old_answer = hashmap_get(d->positive_by_key, rr->key);
        answer = dns_answer_ref(old_answer);

        r = dns_answer_add_extend(&answer, rr, 0, DNS_ANSWER_AUTHENTICATED);
        if (r < 0)
                return log_error_errno(r, "Failed to add trust anchor RR: %m");

        r = hashmap_replace(d->positive_by_key, rr->key, answer);
        if (r < 0)
                return log_error_errno(r, "Failed to add answer to trust anchor: %m");

        old_answer = dns_answer_unref(old_answer);
        answer = NULL;

        return 0;
}

static int dns_trust_anchor_load_negative(DnsTrustAnchor *d, const char *path, unsigned line, const char *s) {
        _cleanup_free_ char *domain = NULL;
        const char *p = s;
        int r;

        assert(d);
        assert(line);

        r = extract_first_word(&p, &domain, NULL, EXTRACT_QUOTES);
        if (r < 0)
                return log_warning_errno(r, "Unable to parse line %s:%u: %m", path, line);

        if (!dns_name_is_valid(domain)) {
                log_warning("Domain name %s is invalid, at line %s:%u, ignoring line.", domain, path, line);
                return -EINVAL;
        }

        if (!isempty(p)) {
                log_warning("Trailing garbage at line %s:%u, ignoring line.", path, line);
                return -EINVAL;
        }

        r = set_ensure_allocated(&d->negative_by_name, &dns_name_hash_ops);
        if (r < 0)
                return r;

        r = set_put(d->negative_by_name, domain);
        if (r < 0)
                return log_oom();
        if (r > 0)
                domain = NULL;

        return 0;
}

static int dns_trust_anchor_load_files(
                DnsTrustAnchor *d,
                const char *suffix,
                int (*loader)(DnsTrustAnchor *d, const char *path, unsigned n, const char *line)) {

        _cleanup_strv_free_ char **files = NULL;
        char **f;
        int r;

        assert(d);
        assert(suffix);
        assert(loader);

        r = conf_files_list_nulstr(&files, suffix, NULL, trust_anchor_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate %s trust anchor files: %m", suffix);

        STRV_FOREACH(f, files) {
                _cleanup_fclose_ FILE *g = NULL;
                char line[LINE_MAX];
                unsigned n = 0;

                g = fopen(*f, "r");
                if (!g) {
                        if (errno == ENOENT)
                                continue;

                        log_warning_errno(errno, "Failed to open %s: %m", *f);
                        continue;
                }

                FOREACH_LINE(line, g, log_warning_errno(errno, "Failed to read %s, ignoring: %m", *f)) {
                        char *l;

                        n++;

                        l = strstrip(line);
                        if (isempty(l))
                                continue;

                        if (*l == ';')
                                continue;

                        (void) loader(d, *f, n, l);
                }
        }

        return 0;
}

static void dns_trust_anchor_dump(DnsTrustAnchor *d) {
        DnsAnswer *a;
        Iterator i;

        assert(d);

        if (hashmap_isempty(d->positive_by_key))
                log_info("No positive trust anchors defined.");
        else {
                log_info("Positive Trust Anchors:");
                HASHMAP_FOREACH(a, d->positive_by_key, i) {
                        DnsResourceRecord *rr;

                        DNS_ANSWER_FOREACH(rr, a)
                                log_info("%s", dns_resource_record_to_string(rr));
                }
        }

        if (set_isempty(d->negative_by_name))
                log_info("No negative trust anchors defined.");
        else {
                char *n;
                log_info("Negative trust anchors:");

                SET_FOREACH(n, d->negative_by_name, i)
                        log_info("%s%s", n, endswith(n, ".") ? "" : ".");
        }
}

int dns_trust_anchor_load(DnsTrustAnchor *d) {
        int r;

        assert(d);

        /* If loading things from disk fails, we don't consider this fatal */
        (void) dns_trust_anchor_load_files(d, ".positive", dns_trust_anchor_load_positive);
        (void) dns_trust_anchor_load_files(d, ".negative", dns_trust_anchor_load_negative);

        /* However, if the built-in DS fails, then we have a problem. */
        r = dns_trust_anchor_add_builtin(d);
        if (r < 0)
                return log_error_errno(r, "Failed to add trust anchor built-in: %m");

        dns_trust_anchor_dump(d);

        return 0;
}

void dns_trust_anchor_flush(DnsTrustAnchor *d) {
        DnsAnswer *a;

        assert(d);

        while ((a = hashmap_steal_first(d->positive_by_key)))
                dns_answer_unref(a);

        d->positive_by_key = hashmap_free(d->positive_by_key);
        d->negative_by_name = set_free_free(d->negative_by_name);
}

int dns_trust_anchor_lookup_positive(DnsTrustAnchor *d, const DnsResourceKey *key, DnsAnswer **ret) {
        DnsAnswer *a;

        assert(d);
        assert(key);
        assert(ret);

        /* We only serve DS and DNSKEY RRs. */
        if (!IN_SET(key->type, DNS_TYPE_DS, DNS_TYPE_DNSKEY))
                return 0;

        a = hashmap_get(d->positive_by_key, key);
        if (!a)
                return 0;

        *ret = dns_answer_ref(a);
        return 1;
}

int dns_trust_anchor_lookup_negative(DnsTrustAnchor *d, const char *name) {
        assert(d);
        assert(name);

        return set_contains(d->negative_by_name, name);
}

static int dns_trust_anchor_remove_revoked(DnsTrustAnchor *d, DnsResourceRecord *rr) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *new_answer = NULL;
        DnsAnswer *old_answer;
        int r;

        old_answer = hashmap_get(d->positive_by_key, rr->key);
        if (!old_answer)
                return 0;

        new_answer = dns_answer_ref(old_answer);

        r = dns_answer_remove_by_rr(&new_answer, rr);
        if (r <= 0)
                return r;

        /* We found the key! Warn the user */
        log_struct(LOG_WARNING,
                   LOG_MESSAGE_ID(SD_MESSAGE_DNSSEC_TRUST_ANCHOR_REVOKED),
                   LOG_MESSAGE("DNSSEC Trust anchor %s has been revoked. Please update the trust anchor, or upgrade your operating system."), strna(dns_resource_record_to_string(rr)),
                   "TRUST_ANCHOR=%s", dns_resource_record_to_string(rr),
                   NULL);

        if (dns_answer_size(new_answer) <= 0) {
                assert_se(hashmap_remove(d->positive_by_key, rr->key) == old_answer);
                dns_answer_unref(old_answer);
                return 1;
        }

        r = hashmap_replace(d->positive_by_key, new_answer->items[0].rr->key, new_answer);
        if (r < 0)
                return r;

        new_answer = NULL;
        dns_answer_unref(old_answer);
        return 1;
}

static int dns_trust_anchor_check_revoked_one(DnsTrustAnchor *d, DnsResourceRecord *revoked_dnskey) {
        DnsAnswer *a;
        int r;

        assert(d);
        assert(revoked_dnskey);
        assert(revoked_dnskey->key->type == DNS_TYPE_DNSKEY);
        assert(revoked_dnskey->dnskey.flags & DNSKEY_FLAG_REVOKE);

        a = hashmap_get(d->positive_by_key, revoked_dnskey->key);
        if (a) {
                DnsResourceRecord *anchor;

                /* First, look for the precise DNSKEY in our trust anchor database */

                DNS_ANSWER_FOREACH(anchor, a) {

                        if (anchor->dnskey.protocol != revoked_dnskey->dnskey.protocol)
                                continue;

                        if (anchor->dnskey.algorithm != revoked_dnskey->dnskey.algorithm)
                                continue;

                        if (anchor->dnskey.key_size != revoked_dnskey->dnskey.key_size)
                                continue;

                        if (((anchor->dnskey.flags ^ revoked_dnskey->dnskey.flags) | DNSKEY_FLAG_REVOKE) != DNSKEY_FLAG_REVOKE)
                                continue;

                        if (memcmp(anchor->dnskey.key, revoked_dnskey->dnskey.key, anchor->dnskey.key_size) != 0)
                                continue;

                        dns_trust_anchor_remove_revoked(d, anchor);
                        break;
                }
        }

        a = hashmap_get(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(revoked_dnskey->key->class, DNS_TYPE_DS, DNS_RESOURCE_KEY_NAME(revoked_dnskey->key)));
        if (a) {
                DnsResourceRecord *anchor;

                /* Second, look for DS RRs matching this DNSKEY in our trust anchor database */

                DNS_ANSWER_FOREACH(anchor, a) {

                        r = dnssec_verify_dnskey(revoked_dnskey, anchor, true);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        dns_trust_anchor_remove_revoked(d, anchor);
                        break;
                }
        }

        return 0;
}

static bool dns_trust_anchor_knows_domain(DnsTrustAnchor *d, const char *name) {
        assert(d);

        /* Returns true if there's an entry for the specified domain
         * name in our trust anchor */

        return
                hashmap_contains(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_DNSKEY, name)) ||
                hashmap_contains(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_DS, name));
}

int dns_trust_anchor_check_revoked(DnsTrustAnchor *d, DnsAnswer *rrs, const DnsResourceKey *key) {
        DnsResourceRecord *dnskey;
        int r;

        assert(d);
        assert(key);

        /* Looks for self-signed DNSKEY RRs in "rrs" that have been revoked. */

        if (key->type != DNS_TYPE_DNSKEY)
                return 0;

        DNS_ANSWER_FOREACH(dnskey, rrs) {
                DnsResourceRecord *rrsig;
                DnssecResult result;

                r = dns_resource_key_equal(key, dnskey->key);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* Is this DNSKEY revoked? */
                if ((dnskey->dnskey.flags & DNSKEY_FLAG_REVOKE) == 0)
                        continue;

                /* Could this be interesting to us at all? If not,
                 * there's no point in looking for and verifying a
                 * self-signed RRSIG. */
                if (!dns_trust_anchor_knows_domain(d, DNS_RESOURCE_KEY_NAME(dnskey->key)))
                        continue;

                /* Look for a self-signed RRSIG */
                DNS_ANSWER_FOREACH(rrsig, rrs) {

                        if (rrsig->key->type != DNS_TYPE_RRSIG)
                                continue;

                        r = dnssec_rrsig_match_dnskey(rrsig, dnskey, true);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        r = dnssec_verify_rrset(rrs, key, rrsig, dnskey, USEC_INFINITY, &result);
                        if (r < 0)
                                return r;
                        if (result != DNSSEC_VALIDATED)
                                continue;

                        /* Bingo! Now, act! */
                        r = dns_trust_anchor_check_revoked_one(d, dnskey);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}
