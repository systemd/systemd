/***
  This file is part of systemd

  Copyright 2016 Zbigniew Jędrzejewski-Szmek

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

#include <net/if.h>

#include "alloc-util.h"
#include "fileio.h"
#include "macro.h"
#include "log.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-rr.h"
#include "string-util.h"

#define HASH_KEY SD_ID128_MAKE(d3,1e,48,90,4b,fa,4c,fe,af,9d,d5,a1,d7,2e,8a,b1)

static uint64_t hash(DnsResourceRecord *rr) {
        struct siphash state;

        siphash24_init(&state, HASH_KEY.bytes);
        dns_resource_record_hash_func(rr, &state);
        return siphash24_finalize(&state);
}

static void test_packet_from_file(const char* filename, bool canonical) {
        _cleanup_free_ char *data = NULL;
        size_t data_size, packet_size, offset;

        assert_se(read_full_file(filename, &data, &data_size) >= 0);
        assert_se(data);
        assert_se(data_size > 8);

        log_info("============== %s %s==============", filename, canonical ? "canonical " : "");

        for (offset = 0; offset < data_size; offset += 8 + packet_size) {
                _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL, *p2 = NULL;
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL, *rr2 = NULL;
                const char *s, *s2;
                uint64_t hash1, hash2;

                packet_size = le64toh( *(uint64_t*)(data + offset) );
                assert_se(packet_size > 0);
                assert_se(offset + 8 + packet_size <= data_size);

                assert_se(dns_packet_new(&p, DNS_PROTOCOL_DNS, 0) >= 0);

                assert_se(dns_packet_append_blob(p, data + offset + 8, packet_size, NULL) >= 0);
                assert_se(dns_packet_read_rr(p, &rr, NULL, NULL) >= 0);

                s = dns_resource_record_to_string(rr);
                assert_se(s);
                puts(s);

                hash1 = hash(rr);

                assert_se(dns_resource_record_to_wire_format(rr, canonical) >= 0);

                assert_se(dns_packet_new(&p2, DNS_PROTOCOL_DNS, 0) >= 0);
                assert_se(dns_packet_append_blob(p2, rr->wire_format, rr->wire_format_size, NULL) >= 0);
                assert_se(dns_packet_read_rr(p2, &rr2, NULL, NULL) >= 0);

                s2 = dns_resource_record_to_string(rr);
                assert_se(s2);
                assert_se(streq(s, s2));

                hash2 = hash(rr);
                assert_se(hash1 == hash2);
        }
}

int main(int argc, char **argv) {
        int i;

        log_parse_environment();

        for (i = 1; i < argc; i++) {
                test_packet_from_file(argv[i], false);
                puts("");
                test_packet_from_file(argv[i], true);
                if (i + 1 < argc)
                        puts("");
        }

        return EXIT_SUCCESS;
}
