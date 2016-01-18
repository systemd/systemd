/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "dns-type.h"
#include "random-util.h"
#include "string-util.h"
#include "time-util.h"

#define DNS_CALL_TIMEOUT_USEC (45*USEC_PER_SEC)

static void test_lookup(sd_bus *bus, const char *name, uint16_t type, const char *result) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *m = NULL;
        int r;

        /* If the name starts with a dot, we prefix one to three random labels */
        if (startswith(name, ".")) {
                uint64_t i, u;

                u = 1 + (random_u64() & 3);
                name ++;

                for (i = 0; i < u; i++) {
                        _cleanup_free_ char *b = NULL;
                        char *x;

                        assert_se(asprintf(&b, "x%" PRIu64 "x", random_u64()));
                        x = strjoin(b, ".", name, NULL);
                        assert_se(x);
                        free(m);
                        name = m = x;
                }
        }

        assert_se(sd_bus_message_new_method_call(
                                  bus,
                                  &req,
                                  "org.freedesktop.resolve1",
                                  "/org/freedesktop/resolve1",
                                  "org.freedesktop.resolve1.Manager",
                                  "ResolveRecord") >= 0);

        assert_se(sd_bus_message_append(req, "isqqt", 0, name, DNS_CLASS_IN, type, UINT64_C(0)) >= 0);

        r = sd_bus_call(bus, req, DNS_CALL_TIMEOUT_USEC, &error, &reply);

        if (r < 0) {
                assert_se(result);
                assert_se(sd_bus_error_has_name(&error, result));
                log_info("[OK] %s/%s resulted in <%s>.", name, dns_type_to_string(type), error.name);
        } else {
                assert_se(!result);
                log_info("[OK] %s/%s succeeded.", name, dns_type_to_string(type));
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

        assert_se(sd_bus_open_system(&bus) >= 0);

        /* Normally signed */
        test_lookup(bus, "www.eurid.eu", DNS_TYPE_A, NULL);
        test_lookup(bus, "sigok.verteiltesysteme.net", DNS_TYPE_A, NULL);

        /* Normally signed, NODATA */
        test_lookup(bus, "www.eurid.eu", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);
        test_lookup(bus, "sigok.verteiltesysteme.net", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* Invalid signature */
        test_lookup(bus, "sigfail.verteiltesysteme.net", DNS_TYPE_A, BUS_ERROR_DNSSEC_FAILED);

        /* Invalid signature, RSA, wildcard */
        test_lookup(bus, ".wilda.rhybar.0skar.cz", DNS_TYPE_A, BUS_ERROR_DNSSEC_FAILED);

        /* Invalid signature, ECDSA, wildcard */
        test_lookup(bus, ".wilda.rhybar.ecdsa.0skar.cz", DNS_TYPE_A, BUS_ERROR_DNSSEC_FAILED);

        /* NXDOMAIN in NSEC domain */
        test_lookup(bus, "hhh.nasa.gov", DNS_TYPE_A, _BUS_ERROR_DNS "NXDOMAIN");

        /* wildcard, NSEC zone */
        test_lookup(bus, ".wilda.nsec.0skar.cz", DNS_TYPE_A, NULL);

        /* wildcard, NSEC zone, NODATA */
        test_lookup(bus, ".wilda.nsec.0skar.cz", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* wildcard, NSEC3 zone */
        test_lookup(bus, ".wilda.0skar.cz", DNS_TYPE_A, NULL);

        /* wildcard, NSEC3 zone, NODATA */
        test_lookup(bus, ".wilda.0skar.cz", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* wildcard, NSEC zone, CNAME */
        test_lookup(bus, ".wild.nsec.0skar.cz", DNS_TYPE_A, NULL);

        /* wildcard, NSEC zone, NODATA, CNAME */
        test_lookup(bus, ".wild.nsec.0skar.cz", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* wildcard, NSEC3 zone, CNAME */
        test_lookup(bus, ".wild.0skar.cz", DNS_TYPE_A, NULL);

        /* wildcard, NSEC3 zone, NODATA, CNAME */
        test_lookup(bus, ".wild.0skar.cz", DNS_TYPE_RP, BUS_ERROR_NO_SUCH_RR);

        /* NODATA due to empty non-terminal in NSEC domain */
        test_lookup(bus, "herndon.nasa.gov", DNS_TYPE_A, BUS_ERROR_NO_SUCH_RR);

        /* NXDOMAIN in NSEC root zone: */
        test_lookup(bus, "jasdhjas.kjkfgjhfjg", DNS_TYPE_A, _BUS_ERROR_DNS "NXDOMAIN");

        /* NXDOMAIN in NSEC3 .com zone: */
        test_lookup(bus, "kjkfgjhfjgsdfdsfd.com", DNS_TYPE_A, _BUS_ERROR_DNS "NXDOMAIN");

        return 0;
}
