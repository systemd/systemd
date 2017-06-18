/***
  This file is part of systemd

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

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

#include "log.h"
#include "resolved-dns-packet.h"

static void test_dns_packet_new(void) {
        size_t i;

        for (i = 0; i < DNS_PACKET_SIZE_MAX + 2; i++) {
                _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

                assert_se(dns_packet_new(&p, DNS_PROTOCOL_DNS, i) == 0);

                log_debug("dns_packet_new: %zu → %zu", i, p->allocated);
                assert_se(p->allocated >= MIN(DNS_PACKET_SIZE_MAX, i));
        }
}

int main(int argc, char **argv) {

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_dns_packet_new();

        return 0;
}
