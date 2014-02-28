/***
  This file is part of systemd.

  Copyright (C) 2014 Axis Communications AB. All rights reserved.

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
#include <arpa/inet.h>

#include "util.h"
#include "ipv4ll-internal.h"

void arp_packet_init(struct ether_arp *arp) {
        assert(arp);

        memzero(arp, sizeof(struct ether_arp));
        /* Header */
        arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER); /* HTYPE */
        arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP); /* PTYPE */
        arp->ea_hdr.ar_hln = ETH_ALEN; /* HLEN */
        arp->ea_hdr.ar_pln = sizeof arp->arp_spa; /* PLEN */
        arp->ea_hdr.ar_op = htons(ARPOP_REQUEST); /* REQUEST */
}

void arp_packet_probe(struct ether_arp *arp, be32_t pa, const struct ether_addr *ha) {
        assert(ha);

        arp_packet_init(arp);
        memcpy(arp->arp_sha, ha, ETH_ALEN);
        memcpy(arp->arp_tpa, &pa, sizeof(pa));
}

void arp_packet_announcement(struct ether_arp *arp, be32_t pa, const struct ether_addr *ha) {
        assert(ha);

        arp_packet_init(arp);
        memcpy(arp->arp_sha, ha, ETH_ALEN);
        memcpy(arp->arp_tpa, &pa, sizeof(pa));
        memcpy(arp->arp_spa, &pa, sizeof(pa));
}

int arp_packet_verify_headers(struct ether_arp *arp) {
        assert(arp);

        if (arp->ea_hdr.ar_hrd != htons(ARPHRD_ETHER)) {
                log_ipv4ll(NULL, "ignoring packet: header is not ARPHRD_ETHER");
                return -EINVAL;
        }
        if (arp->ea_hdr.ar_pro != htons(ETHERTYPE_IP)) {
                log_ipv4ll(NULL, "ignoring packet: protocol is not ETHERTYPE_IP");
                return -EINVAL;
        }
        if (arp->ea_hdr.ar_op != htons(ARPOP_REQUEST) &&
            arp->ea_hdr.ar_op != htons(ARPOP_REPLY)) {
                log_ipv4ll(NULL, "ignoring packet: operation is not ARPOP_REQUEST or ARPOP_REPLY");
                return -EINVAL;
        }

        return 0;
}
