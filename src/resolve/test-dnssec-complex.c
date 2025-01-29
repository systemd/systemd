/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ip.h>

#include "sd-bus.h"

#include "af-list.h"
#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-locator.h"
#include "dns-type.h"
#include "random-util.h"
#include "resolved-def.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"

static void prefix_random(const char *name, char **ret) {
        uint64_t i, u;
        char *m = NULL;

        u = 1 + (random_u64() & 3);

        for (i = 0; i < u; i++) {
                _cleanup_free_ char *b = NULL;
                char *x;

                assert_se(asprintf(&b, "x%" PRIu64 "x", random_u64()));
                x = strjoin(b, ".", name);
                assert_se(x);

                free(m);
                m = x;
        }

        *ret = m;
 }

static void test_rr_lookup(sd_bus *bus, const char *name, uint16_t type, const char *result) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *m = NULL;
        int r;

        /* If the name starts with a dot, we prefix one to three random labels */
        if (startswith(name, ".")) {
                prefix_random(name + 1, &m);
                name = m;
        }

        assert_se(bus_message_new_method_call(bus, &req, bus_resolve_mgr, "ResolveRecord") >= 0);

        assert_se(sd_bus_message_append(req, "isqqt", 0, name, DNS_CLASS_IN, type, UINT64_C(0)) >= 0);

        r = sd_bus_call(bus, req, SD_RESOLVED_QUERY_TIMEOUT_USEC, &error, &reply);

        if (r < 0) {
                assert_se(result);
                assert_se(sd_bus_error_has_name(&error, result));
                log_info("[OK] %s/%s resulted in <%s>.", name, dns_type_to_string(type), error.name);
        } else {
                assert_se(!result);
                log_info("[OK] %s/%s succeeded.", name, dns_type_to_string(type));
        }
}

static void test_hostname_lookup(sd_bus *bus, const char *name, int family, const char *result) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *m = NULL;
        const char *af;
        int r;

        af = family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(family);

        /* If the name starts with a dot, we prefix one to three random labels */
        if (startswith(name, ".")) {
                prefix_random(name + 1, &m);
                name = m;
        }

        assert_se(bus_message_new_method_call(bus, &req, bus_resolve_mgr, "ResolveHostname") >= 0);

        assert_se(sd_bus_message_append(req, "isit", 0, name, family, UINT64_C(0)) >= 0);

        r = sd_bus_call(bus, req, SD_RESOLVED_QUERY_TIMEOUT_USEC, &error, &reply);

        if (r < 0) {
                assert_se(result);
                assert_se(sd_bus_error_has_name(&error, result));
                log_info("[OK] %s/%s resulted in <%s>.", name, af, error.name);
        } else {
                assert_se(!result);
                log_info("[OK] %s/%s succeeded.", name, af);
        }
}

int main(int argc, char* argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

        /* Note that this is a manual test as it requires:
         *
         *    Full network access
         *    A DNSSEC capable DNS server
         *    That zones contacted are still set up as they were when I wrote this.
         */

        test_setup_logging(LOG_DEBUG);

        assert_se(sd_bus_open_system(&bus) >= 0);

        /* Normally signed */
        test_rr_lookup(bus, "www.eurid.eu", DNS_TYPE_A, NULL);
        test_hostname_lookup(bus, "www.eurid.eu", AF_UNSPEC, NULL);

        test_rr_lookup(bus, "sigok.verteiltesysteme.net", DNS_TYPE_A, NULL);
        test_hostname_lookup(bus, "sigok.verteiltesysteme.net", AF_UNSPEC, NULL);

        /* Normally signed, NODATA */
        test_rr_lookup(bus, "www.eurid.eu", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);
        test_rr_lookup(bus, "sigok.verteiltesysteme.net", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* Invalid signature */
        test_rr_lookup(bus, "sigfail.verteiltesysteme.net", DNS_TYPE_A, BUS_ERROR_DNSSEC_FAILED);
        test_hostname_lookup(bus, "sigfail.verteiltesysteme.net", AF_INET, BUS_ERROR_DNSSEC_FAILED);

        /* Invalid signature, RSA, wildcard */
        test_rr_lookup(bus, ".wilda.rhybar.0skar.cz", DNS_TYPE_A, BUS_ERROR_DNSSEC_FAILED);
        test_hostname_lookup(bus, ".wilda.rhybar.0skar.cz", AF_INET, BUS_ERROR_DNSSEC_FAILED);

        /* Invalid signature, ECDSA, wildcard */
        test_rr_lookup(bus, ".wilda.rhybar.ecdsa.0skar.cz", DNS_TYPE_A, BUS_ERROR_DNSSEC_FAILED);
        test_hostname_lookup(bus, ".wilda.rhybar.ecdsa.0skar.cz", AF_INET, BUS_ERROR_DNSSEC_FAILED);

        /* Missing DS for DNSKEY */
        test_rr_lookup(bus, "www.dnssec-bogus.sg", DNS_TYPE_A, BUS_ERROR_DNSSEC_FAILED);
        test_hostname_lookup(bus, "www.dnssec-bogus.sg", AF_INET, BUS_ERROR_DNSSEC_FAILED);

        /* NXDOMAIN in NSEC domain */
        test_rr_lookup(bus, "hhh.nasa.gov", DNS_TYPE_A, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, "hhh.nasa.gov", AF_UNSPEC, BUS_ERROR_DNS_NXDOMAIN);
        test_rr_lookup(bus, "_pgpkey-https._tcp.hkps.pool.sks-keyservers.net", DNS_TYPE_SRV, BUS_ERROR_DNS_NXDOMAIN);

        /* wildcard, NSEC zone */
        test_rr_lookup(bus, ".wilda.nsec.0skar.cz", DNS_TYPE_A, NULL);
        test_hostname_lookup(bus, ".wilda.nsec.0skar.cz", AF_INET, NULL);

        /* wildcard, NSEC zone, NODATA */
        test_rr_lookup(bus, ".wilda.nsec.0skar.cz", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* wildcard, NSEC3 zone */
        test_rr_lookup(bus, ".wilda.0skar.cz", DNS_TYPE_A, NULL);
        test_hostname_lookup(bus, ".wilda.0skar.cz", AF_INET, NULL);

        /* wildcard, NSEC3 zone, NODATA */
        test_rr_lookup(bus, ".wilda.0skar.cz", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* wildcard, NSEC zone, CNAME */
        test_rr_lookup(bus, ".wild.nsec.0skar.cz", DNS_TYPE_A, NULL);
        test_hostname_lookup(bus, ".wild.nsec.0skar.cz", AF_UNSPEC, NULL);
        test_hostname_lookup(bus, ".wild.nsec.0skar.cz", AF_INET, NULL);

        /* wildcard, NSEC zone, NODATA, CNAME */
        test_rr_lookup(bus, ".wild.nsec.0skar.cz", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* wildcard, NSEC3 zone, CNAME */
        test_rr_lookup(bus, ".wild.0skar.cz", DNS_TYPE_A, NULL);
        test_hostname_lookup(bus, ".wild.0skar.cz", AF_UNSPEC, NULL);
        test_hostname_lookup(bus, ".wild.0skar.cz", AF_INET, NULL);

        /* wildcard, NSEC3 zone, NODATA, CNAME */
        test_rr_lookup(bus, ".wild.0skar.cz", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* NODATA due to empty non-terminal in NSEC domain */
        test_rr_lookup(bus, "herndon.nasa.gov", DNS_TYPE_A, BUS_ERROR_NO_SUCH_RR);
        test_hostname_lookup(bus, "herndon.nasa.gov", AF_UNSPEC, BUS_ERROR_NO_SUCH_RR);
        test_hostname_lookup(bus, "herndon.nasa.gov", AF_INET, BUS_ERROR_NO_SUCH_RR);
        test_hostname_lookup(bus, "herndon.nasa.gov", AF_INET6, BUS_ERROR_NO_SUCH_RR);

        /* NXDOMAIN in NSEC root zone: */
        test_rr_lookup(bus, "jasdhjas.kjkfgjhfjg", DNS_TYPE_A, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, "jasdhjas.kjkfgjhfjg", AF_UNSPEC, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, "jasdhjas.kjkfgjhfjg", AF_INET, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, "jasdhjas.kjkfgjhfjg", AF_INET6, BUS_ERROR_DNS_NXDOMAIN);

        /* NXDOMAIN in NSEC3 .com zone: */
        test_rr_lookup(bus, "kjkfgjhfjgsdfdsfd.com", DNS_TYPE_A, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, "kjkfgjhfjgsdfdsfd.com", AF_INET, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, "kjkfgjhfjgsdfdsfd.com", AF_INET6, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, "kjkfgjhfjgsdfdsfd.com", AF_UNSPEC, BUS_ERROR_DNS_NXDOMAIN);

        /* Unsigned A */
        test_rr_lookup(bus, "poettering.de", DNS_TYPE_A, NULL);
        test_rr_lookup(bus, "poettering.de", DNS_TYPE_AAAA, NULL);
        test_hostname_lookup(bus, "poettering.de", AF_UNSPEC, NULL);
        test_hostname_lookup(bus, "poettering.de", AF_INET, NULL);
        test_hostname_lookup(bus, "poettering.de", AF_INET6, NULL);

#if HAVE_LIBIDN2 || HAVE_LIBIDN
        /* Unsigned A with IDNA conversion necessary */
        test_hostname_lookup(bus, "pöttering.de", AF_UNSPEC, NULL);
        test_hostname_lookup(bus, "pöttering.de", AF_INET, NULL);
        test_hostname_lookup(bus, "pöttering.de", AF_INET6, NULL);
#endif

        /* DNAME, pointing to NXDOMAIN */
        test_rr_lookup(bus, ".ireallyhpoethisdoesnexist.xn--kprw13d.", DNS_TYPE_A, BUS_ERROR_DNS_NXDOMAIN);
        test_rr_lookup(bus, ".ireallyhpoethisdoesnexist.xn--kprw13d.", DNS_TYPE_RP, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, ".ireallyhpoethisdoesntexist.xn--kprw13d.", AF_UNSPEC, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, ".ireallyhpoethisdoesntexist.xn--kprw13d.", AF_INET, BUS_ERROR_DNS_NXDOMAIN);
        test_hostname_lookup(bus, ".ireallyhpoethisdoesntexist.xn--kprw13d.", AF_INET6, BUS_ERROR_DNS_NXDOMAIN);

        return 0;
}
