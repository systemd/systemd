/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Susant Sahani

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

#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "macro.h"
#include "lldp.h"
#include "lldp-tlv.h"

#define TEST_LLDP_PORT "em1"
#define TEST_LLDP_TYPE_SYSTEM_NAME "systemd-lldp"
#define TEST_LLDP_TYPE_SYSTEM_DESC "systemd-lldp-desc"

static struct ether_addr mac_addr = {
        .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
};

static int lldp_build_tlv_packet(tlv_packet **ret) {
        _cleanup_tlv_packet_free_ tlv_packet *m = NULL;
        const uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
        struct ether_header ether = {
                .ether_type = htons(ETHERTYPE_LLDP),
        };

        /* Append ethernet header */
        memcpy(&ether.ether_dhost, lldp_dst, ETHER_ADDR_LEN);
        memcpy(&ether.ether_shost, &mac_addr, ETHER_ADDR_LEN);

        assert_se(tlv_packet_new(&m) >= 0);

        assert_se(tlv_packet_append_bytes(m, &ether, sizeof(struct ether_header)) >= 0);

        assert_se(lldp_tlv_packet_open_container(m, LLDP_TYPE_CHASSIS_ID) >= 0);

        assert_se(tlv_packet_append_u8(m, LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS) >= 0);
        assert_se(tlv_packet_append_bytes(m, &mac_addr, ETHER_ADDR_LEN) >= 0);

        assert_se(lldp_tlv_packet_close_container(m) >= 0);

        /* port name */
        assert_se(lldp_tlv_packet_open_container(m, LLDP_TYPE_PORT_ID) >= 0);

        assert_se(tlv_packet_append_u8(m, LLDP_PORT_SUBTYPE_INTERFACE_NAME) >= 0);
        assert_se(tlv_packet_append_bytes(m, TEST_LLDP_PORT, strlen(TEST_LLDP_PORT) + 1) >= 0);

        assert_se(lldp_tlv_packet_close_container(m) >= 0);

        /* ttl */
        assert_se(lldp_tlv_packet_open_container(m, LLDP_TYPE_TTL) >= 0);

        assert_se(tlv_packet_append_u16(m, 170) >= 0);

        assert_se(lldp_tlv_packet_close_container(m) >= 0);

        /* system name */
        assert_se(lldp_tlv_packet_open_container(m, LLDP_TYPE_SYSTEM_NAME) >= 0);

        assert_se(tlv_packet_append_bytes(m, TEST_LLDP_TYPE_SYSTEM_NAME,
                                          strlen(TEST_LLDP_TYPE_SYSTEM_NAME)) >= 0);
        assert_se(lldp_tlv_packet_close_container(m) >= 0);

        /* system descrition */
        assert_se(lldp_tlv_packet_open_container(m, LLDP_TYPE_SYSTEM_DESCRIPTION) >= 0);

        assert_se(tlv_packet_append_bytes(m, TEST_LLDP_TYPE_SYSTEM_DESC,
                                          strlen(TEST_LLDP_TYPE_SYSTEM_DESC)) >= 0);

        assert_se(lldp_tlv_packet_close_container(m) >= 0);

        /* Mark end of packet */
        assert_se(lldp_tlv_packet_open_container(m, LLDP_TYPE_END) >= 0);
        assert_se(lldp_tlv_packet_close_container(m) >= 0);

        *ret = m;

        m = NULL;

        return 0;
}

static int lldp_parse_chassis_tlv(tlv_packet *m, uint8_t *type) {
        uint8_t *p, subtype;
        uint16_t length;

        assert_se(lldp_tlv_packet_enter_container(m, LLDP_TYPE_CHASSIS_ID) >= 0);
        assert_se(tlv_packet_read_u8(m, &subtype) >= 0);

        switch (subtype) {
        case LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS:

                *type = LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS;
                assert_se(tlv_packet_read_bytes(m, &p, &length) >= 0);

                assert_se(memcmp(p, &mac_addr.ether_addr_octet, ETHER_ADDR_LEN) == 0);

                break;
        default:
                assert_not_reached("Unhandled option");
        }

        assert_se(lldp_tlv_packet_exit_container(m) >= 0);

        return 0;
}

static int lldp_parse_port_id_tlv(tlv_packet *m) {
        _cleanup_free_ char *p = NULL;
        char *str = NULL;
        uint16_t length;
        uint8_t subtype;

        assert_se(lldp_tlv_packet_enter_container(m, LLDP_TYPE_PORT_ID) >= 0);

        assert_se(tlv_packet_read_u8(m, &subtype) >= 0);

        switch (subtype) {
        case LLDP_PORT_SUBTYPE_INTERFACE_NAME:
                assert_se(tlv_packet_read_string(m, &str, &length) >= 0);

                p = strndup(str, length-1);
                assert_se(p);

                assert_se(streq(p, TEST_LLDP_PORT) == 1);
                break;
        default:
                assert_not_reached("Unhandled option");
        }

        assert_se(lldp_tlv_packet_exit_container(m) >= 0);

        return 0;
}

static int lldp_parse_system_name_tlv(tlv_packet *m) {
        _cleanup_free_ char *p = NULL;
        char *str = NULL;
        uint16_t length;

        assert_se(lldp_tlv_packet_enter_container(m, LLDP_TYPE_SYSTEM_NAME) >= 0);
        assert_se(tlv_packet_read_string(m, &str, &length) >= 0);

        p = strndup(str, length);
        assert_se(p);

        assert_se(streq(p, TEST_LLDP_TYPE_SYSTEM_NAME) == 1);

        assert_se(lldp_tlv_packet_exit_container(m) >= 0);

        return 1;
}

static int lldp_parse_system_desc_tlv(tlv_packet *m) {
        _cleanup_free_ char *p = NULL;
        char *str = NULL;
        uint16_t length;

        assert_se(lldp_tlv_packet_enter_container(m, LLDP_TYPE_SYSTEM_DESCRIPTION) >= 0);
        assert_se(tlv_packet_read_string(m, &str, &length) >= 0);

        p = strndup(str, length);
        assert_se(p);

        assert_se(streq(p, TEST_LLDP_TYPE_SYSTEM_DESC) == 1);

        assert_se(lldp_tlv_packet_exit_container(m) >= 0);

        return 0;
}

static int lldp_parse_ttl_tlv(tlv_packet *m) {
        uint16_t ttl;

        assert_se(lldp_tlv_packet_enter_container(m, LLDP_TYPE_TTL) >= 0);
        assert_se(tlv_packet_read_u16(m, &ttl) >= 0);

        assert_se(ttl == 170);

        assert_se(lldp_tlv_packet_exit_container(m) >= 0);

        return 0;
}

static int lldp_parse_tlv_packet(tlv_packet *m, int len) {
        uint8_t subtype;

        assert_se(tlv_packet_parse_pdu(m, len) >= 0);
        assert_se(lldp_parse_chassis_tlv(m, &subtype) >= 0);
        assert_se(lldp_parse_port_id_tlv(m) >= 0);
        assert_se(lldp_parse_system_name_tlv(m) >= 0);
        assert_se(lldp_parse_ttl_tlv(m) >= 0);
        assert_se(lldp_parse_system_desc_tlv(m) >= 0);

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_tlv_packet_free_ tlv_packet *tlv = NULL;

        /* form a packet */
        lldp_build_tlv_packet(&tlv);

        /* parse the packet */
        tlv_packet_parse_pdu(tlv, tlv->length);

        /* verify */
        lldp_parse_tlv_packet(tlv, tlv->length);

        return 0;
}
