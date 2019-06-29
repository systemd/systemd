/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-messages.h"

#include "alloc-util.h"
#include "conf-files.h"
#include "def.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-trust-anchor.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"

static const char trust_anchor_dirs[] = CONF_PATHS_NULSTR("dnssec-trust-anchors.d");

/* The first DS RR from https://data.iana.org/root-anchors/root-anchors.xml, retrieved December 2015 */
static const uint8_t root_digest1[] =
        { 0x49, 0xAA, 0xC1, 0x1D, 0x7B, 0x6F, 0x64, 0x46, 0x70, 0x2E, 0x54, 0xA1, 0x60, 0x73, 0x71, 0x60,
          0x7A, 0x1A, 0x41, 0x85, 0x52, 0x00, 0xFD, 0x2C, 0xE1, 0xCD, 0xDE, 0x32, 0xF2, 0x4E, 0x8F, 0xB5 };

/* The second DS RR from https://data.iana.org/root-anchors/root-anchors.xml, retrieved February 2017 */
static const uint8_t root_digest2[] =
        { 0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
          0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D };

static bool dns_trust_anchor_knows_domain_positive(DnsTrustAnchor *d, const char *name) {
        assert(d);

        /* Returns true if there's an entry for the specified domain
         * name in our trust anchor */

        return
                hashmap_contains(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_DNSKEY, name)) ||
                hashmap_contains(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_DS, name));
}

static int add_root_ksk(
                DnsAnswer *answer,
                DnsResourceKey *key,
                uint16_t key_tag,
                uint8_t algorithm,
                uint8_t digest_type,
                const void *digest,
                size_t digest_size) {

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        int r;

        rr = dns_resource_record_new(key);
        if (!rr)
                return -ENOMEM;

        rr->ds.key_tag = key_tag;
        rr->ds.algorithm = algorithm;
        rr->ds.digest_type = digest_type;
        rr->ds.digest_size = digest_size;
        rr->ds.digest = memdup(digest, rr->ds.digest_size);
        if (!rr->ds.digest)
                return  -ENOMEM;

        r = dns_answer_add(answer, rr, 0, DNS_ANSWER_AUTHENTICATED);
        if (r < 0)
                return r;

        return 0;
}

static int dns_trust_anchor_add_builtin_positive(DnsTrustAnchor *d) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        int r;

        assert(d);

        r = hashmap_ensure_allocated(&d->positive_by_key, &dns_resource_key_hash_ops);
        if (r < 0)
                return r;

        /* Only add the built-in trust anchor if there's neither a DS nor a DNSKEY defined for the root domain. That
         * way users have an easy way to override the root domain DS/DNSKEY data. */
        if (dns_trust_anchor_knows_domain_positive(d, "."))
                return 0;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DS, "");
        if (!key)
                return -ENOMEM;

        answer = dns_answer_new(2);
        if (!answer)
                return -ENOMEM;

        /* Add the two RRs from https://data.iana.org/root-anchors/root-anchors.xml */
        r = add_root_ksk(answer, key, 19036, DNSSEC_ALGORITHM_RSASHA256, DNSSEC_DIGEST_SHA256, root_digest1, sizeof(root_digest1));
        if (r < 0)
                return r;

        r = add_root_ksk(answer, key, 20326, DNSSEC_ALGORITHM_RSASHA256, DNSSEC_DIGEST_SHA256, root_digest2, sizeof(root_digest2));
        if (r < 0)
                return r;

        r = hashmap_put(d->positive_by_key, key, answer);
        if (r < 0)
                return r;

        answer = NULL;
        return 0;
}

static int dns_trust_anchor_add_builtin_negative(DnsTrustAnchor *d) {

        static const char private_domains[] =
                /* RFC 6761 says that .test is a special domain for
                 * testing and not to be installed in the root zone */
                "test\0"

                /* RFC 6761 says that these reverse IP lookup ranges
                 * are for private addresses, and hence should not
                 * show up in the root zone */
                "10.in-addr.arpa\0"
                "16.172.in-addr.arpa\0"
                "17.172.in-addr.arpa\0"
                "18.172.in-addr.arpa\0"
                "19.172.in-addr.arpa\0"
                "20.172.in-addr.arpa\0"
                "21.172.in-addr.arpa\0"
                "22.172.in-addr.arpa\0"
                "23.172.in-addr.arpa\0"
                "24.172.in-addr.arpa\0"
                "25.172.in-addr.arpa\0"
                "26.172.in-addr.arpa\0"
                "27.172.in-addr.arpa\0"
                "28.172.in-addr.arpa\0"
                "29.172.in-addr.arpa\0"
                "30.172.in-addr.arpa\0"
                "31.172.in-addr.arpa\0"
                "168.192.in-addr.arpa\0"

                /* The same, but for IPv6. */
                "d.f.ip6.arpa\0"

                /* RFC 6762 reserves the .local domain for Multicast
                 * DNS, it hence cannot appear in the root zone. (Note
                 * that we by default do not route .local traffic to
                 * DNS anyway, except when a configured search domain
                 * suggests so.) */
                "local\0"

                /* These two are well known, popular private zone
                 * TLDs, that are blocked from delegation, according
                 * to:
                 * http://icannwiki.com/Name_Collision#NGPC_Resolution
                 *
                 * There's also ongoing work on making this official
                 * in an RRC:
                 * https://www.ietf.org/archive/id/draft-chapin-additional-reserved-tlds-02.txt */
                "home\0"
                "corp\0"

                /* The following four TLDs are suggested for private
                 * zones in RFC 6762, Appendix G, and are hence very
                 * unlikely to be made official TLDs any day soon */
                "lan\0"
                "intranet\0"
                "internal\0"
                "private\0";

        const char *name;
        int r;

        assert(d);

        /* Only add the built-in trust anchor if there's no negative
         * trust anchor defined at all. This enables easy overriding
         * of negative trust anchors. */

        if (set_size(d->negative_by_name) > 0)
                return 0;

        r = set_ensure_allocated(&d->negative_by_name, &dns_name_hash_ops);
        if (r < 0)
                return r;

        /* We add a couple of domains as default negative trust
         * anchors, where it's very unlikely they will be installed in
         * the root zone. If they exist they must be private, and thus
         * unsigned. */

        NULSTR_FOREACH(name, private_domains) {

                if (dns_trust_anchor_knows_domain_positive(d, name))
                        continue;

                r = set_put_strdup(d->negative_by_name, name);
                if (r < 0)
                        return r;
        }

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

        r = extract_first_word(&p, &domain, NULL, EXTRACT_UNQUOTE);
        if (r < 0)
                return log_warning_errno(r, "Unable to parse domain in line %s:%u: %m", path, line);

        r = dns_name_is_valid(domain);
        if (r < 0)
                return log_warning_errno(r, "Failed to check validity of domain name '%s', at line %s:%u, ignoring line: %m", domain, path, line);
        if (r == 0) {
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
                _cleanup_free_ char *key_tag = NULL, *algorithm = NULL, *digest_type = NULL;
                _cleanup_free_ void *dd = NULL;
                uint16_t kt;
                int a, dt;
                size_t l;

                r = extract_many_words(&p, NULL, 0, &key_tag, &algorithm, &digest_type, NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse DS parameters on line %s:%u: %m", path, line);
                        return -EINVAL;
                }
                if (r != 3) {
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

                if (isempty(p)) {
                        log_warning("Missing DS digest on line %s:%u", path, line);
                        return -EINVAL;
                }

                r = unhexmem(p, strlen(p), &dd, &l);
                if (r < 0) {
                        log_warning("Failed to parse DS digest %s on line %s:%u", p, path, line);
                        return -EINVAL;
                }

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DS, domain);
                if (!rr)
                        return log_oom();

                rr->ds.key_tag = kt;
                rr->ds.algorithm = a;
                rr->ds.digest_type = dt;
                rr->ds.digest_size = l;
                rr->ds.digest = TAKE_PTR(dd);

        } else if (strcaseeq(type, "DNSKEY")) {
                _cleanup_free_ char *flags = NULL, *protocol = NULL, *algorithm = NULL;
                _cleanup_free_ void *k = NULL;
                uint16_t f;
                size_t l;
                int a;

                r = extract_many_words(&p, NULL, 0, &flags, &protocol, &algorithm, NULL);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse DNSKEY parameters on line %s:%u: %m", path, line);
                if (r != 3) {
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

                if (isempty(p)) {
                        log_warning("Missing DNSKEY key on line %s:%u", path, line);
                        return -EINVAL;
                }

                r = unbase64mem(p, strlen(p), &k, &l);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse DNSKEY key data %s on line %s:%u", p, path, line);

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNSKEY, domain);
                if (!rr)
                        return log_oom();

                rr->dnskey.flags = f;
                rr->dnskey.protocol = 3;
                rr->dnskey.algorithm = a;
                rr->dnskey.key_size = l;
                rr->dnskey.key = TAKE_PTR(k);

        } else {
                log_warning("RR type %s is not supported, ignoring line %s:%u.", type, path, line);
                return -EINVAL;
        }

        r = hashmap_ensure_allocated(&d->positive_by_key, &dns_resource_key_hash_ops);
        if (r < 0)
                return log_oom();

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

        r = extract_first_word(&p, &domain, NULL, EXTRACT_UNQUOTE);
        if (r < 0)
                return log_warning_errno(r, "Unable to parse line %s:%u: %m", path, line);

        r = dns_name_is_valid(domain);
        if (r < 0)
                return log_warning_errno(r, "Failed to check validity of domain name '%s', at line %s:%u, ignoring line: %m", domain, path, line);
        if (r == 0) {
                log_warning("Domain name %s is invalid, at line %s:%u, ignoring line.", domain, path, line);
                return -EINVAL;
        }

        if (!isempty(p)) {
                log_warning("Trailing garbage at line %s:%u, ignoring line.", path, line);
                return -EINVAL;
        }

        r = set_ensure_allocated(&d->negative_by_name, &dns_name_hash_ops);
        if (r < 0)
                return log_oom();

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

        r = conf_files_list_nulstr(&files, suffix, NULL, 0, trust_anchor_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate %s trust anchor files: %m", suffix);

        STRV_FOREACH(f, files) {
                _cleanup_fclose_ FILE *g = NULL;
                unsigned n = 0;

                g = fopen(*f, "r");
                if (!g) {
                        if (errno == ENOENT)
                                continue;

                        log_warning_errno(errno, "Failed to open '%s', ignoring: %m", *f);
                        continue;
                }

                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        char *l;

                        r = read_line(g, LONG_LINE_MAX, &line);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to read '%s', ignoring: %m", *f);
                                break;
                        }
                        if (r == 0)
                                break;

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

static int domain_name_cmp(char * const *a, char * const *b) {
        return dns_name_compare_func(*a, *b);
}

static int dns_trust_anchor_dump(DnsTrustAnchor *d) {
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
                _cleanup_free_ char **l = NULL, *j = NULL;

                l = set_get_strv(d->negative_by_name);
                if (!l)
                        return log_oom();

                typesafe_qsort(l, set_size(d->negative_by_name), domain_name_cmp);

                j = strv_join(l, " ");
                if (!j)
                        return log_oom();

                log_info("Negative trust anchors: %s", j);
        }

        return 0;
}

int dns_trust_anchor_load(DnsTrustAnchor *d) {
        int r;

        assert(d);

        /* If loading things from disk fails, we don't consider this fatal */
        (void) dns_trust_anchor_load_files(d, ".positive", dns_trust_anchor_load_positive);
        (void) dns_trust_anchor_load_files(d, ".negative", dns_trust_anchor_load_negative);

        /* However, if the built-in DS fails, then we have a problem. */
        r = dns_trust_anchor_add_builtin_positive(d);
        if (r < 0)
                return log_error_errno(r, "Failed to add built-in positive trust anchor: %m");

        r = dns_trust_anchor_add_builtin_negative(d);
        if (r < 0)
                return log_error_errno(r, "Failed to add built-in negative trust anchor: %m");

        dns_trust_anchor_dump(d);

        return 0;
}

void dns_trust_anchor_flush(DnsTrustAnchor *d) {
        assert(d);

        d->positive_by_key = hashmap_free_with_destructor(d->positive_by_key, dns_answer_unref);
        d->revoked_by_rr = set_free_with_destructor(d->revoked_by_rr, dns_resource_record_unref);
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
        int r;

        assert(d);
        assert(name);

        for (;;) {
                /* If the domain is listed as-is in the NTA database, then that counts */
                if (set_contains(d->negative_by_name, name))
                        return true;

                /* If the domain isn't listed as NTA, but is listed as positive trust anchor, then that counts. See RFC
                 * 7646, section 1.1 */
                if (hashmap_contains(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_DS, name)))
                        return false;

                if (hashmap_contains(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_KEY, name)))
                        return false;

                /* And now, let's look at the parent, and check that too */
                r = dns_name_parent(&name);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
        }

        return false;
}

static int dns_trust_anchor_revoked_put(DnsTrustAnchor *d, DnsResourceRecord *rr) {
        int r;

        assert(d);

        r = set_ensure_allocated(&d->revoked_by_rr, &dns_resource_record_hash_ops);
        if (r < 0)
                return r;

        r = set_put(d->revoked_by_rr, rr);
        if (r < 0)
                return r;
        if (r > 0)
                dns_resource_record_ref(rr);

        return r;
}

static int dns_trust_anchor_remove_revoked(DnsTrustAnchor *d, DnsResourceRecord *rr) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *new_answer = NULL;
        DnsAnswer *old_answer;
        int r;

        /* Remember that this is a revoked trust anchor RR */
        r = dns_trust_anchor_revoked_put(d, rr);
        if (r < 0)
                return r;

        /* Remove this from the positive trust anchor */
        old_answer = hashmap_get(d->positive_by_key, rr->key);
        if (!old_answer)
                return 0;

        new_answer = dns_answer_ref(old_answer);

        r = dns_answer_remove_by_rr(&new_answer, rr);
        if (r <= 0)
                return r;

        /* We found the key! Warn the user */
        log_struct(LOG_WARNING,
                   "MESSAGE_ID=" SD_MESSAGE_DNSSEC_TRUST_ANCHOR_REVOKED_STR,
                   LOG_MESSAGE("DNSSEC trust anchor %s has been revoked.\n"
                               "Please update the trust anchor, or upgrade your operating system.",
                               strna(dns_resource_record_to_string(rr))),
                   "TRUST_ANCHOR=%s", dns_resource_record_to_string(rr));

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

                        /* Note that we allow the REVOKE bit to be
                         * different! It will be set in the revoked
                         * key, but unset in our version of it */
                        if (((anchor->dnskey.flags ^ revoked_dnskey->dnskey.flags) | DNSKEY_FLAG_REVOKE) != DNSKEY_FLAG_REVOKE)
                                continue;

                        if (memcmp(anchor->dnskey.key, revoked_dnskey->dnskey.key, anchor->dnskey.key_size) != 0)
                                continue;

                        dns_trust_anchor_remove_revoked(d, anchor);
                        break;
                }
        }

        a = hashmap_get(d->positive_by_key, &DNS_RESOURCE_KEY_CONST(revoked_dnskey->key->class, DNS_TYPE_DS, dns_resource_key_name(revoked_dnskey->key)));
        if (a) {
                DnsResourceRecord *anchor;

                /* Second, look for DS RRs matching this DNSKEY in our trust anchor database */

                DNS_ANSWER_FOREACH(anchor, a) {

                        /* We set mask_revoke to true here, since our
                         * DS fingerprint will be the one of the
                         * unrevoked DNSKEY, but the one we got passed
                         * here has the bit set. */
                        r = dnssec_verify_dnskey_by_ds(revoked_dnskey, anchor, true);
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

int dns_trust_anchor_check_revoked(DnsTrustAnchor *d, DnsResourceRecord *dnskey, DnsAnswer *rrs) {
        DnsResourceRecord *rrsig;
        int r;

        assert(d);
        assert(dnskey);

        /* Looks if "dnskey" is a self-signed RR that has been revoked
         * and matches one of our trust anchor entries. If so, removes
         * it from the trust anchor and returns > 0. */

        if (dnskey->key->type != DNS_TYPE_DNSKEY)
                return 0;

        /* Is this DNSKEY revoked? */
        if ((dnskey->dnskey.flags & DNSKEY_FLAG_REVOKE) == 0)
                return 0;

        /* Could this be interesting to us at all? If not,
         * there's no point in looking for and verifying a
         * self-signed RRSIG. */
        if (!dns_trust_anchor_knows_domain_positive(d, dns_resource_key_name(dnskey->key)))
                return 0;

        /* Look for a self-signed RRSIG in the other rrs belonging to this DNSKEY */
        DNS_ANSWER_FOREACH(rrsig, rrs) {
                DnssecResult result;

                if (rrsig->key->type != DNS_TYPE_RRSIG)
                        continue;

                r = dnssec_rrsig_match_dnskey(rrsig, dnskey, true);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = dnssec_verify_rrset(rrs, dnskey->key, rrsig, dnskey, USEC_INFINITY, &result);
                if (r < 0)
                        return r;
                if (result != DNSSEC_VALIDATED)
                        continue;

                /* Bingo! This is a revoked self-signed DNSKEY. Let's
                 * see if this precise one exists in our trust anchor
                 * database, too. */
                r = dns_trust_anchor_check_revoked_one(d, dnskey);
                if (r < 0)
                        return r;

                return 1;
        }

        return 0;
}

int dns_trust_anchor_is_revoked(DnsTrustAnchor *d, DnsResourceRecord *rr) {
        assert(d);

        if (!IN_SET(rr->key->type, DNS_TYPE_DS, DNS_TYPE_DNSKEY))
                return 0;

        return set_contains(d->revoked_by_rr, rr);
}
