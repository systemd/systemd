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

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>

#include "sd-event.h"
#include "sd-lldp.h"

#include "alloc-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "lldp-network.h"
#include "lldp-tlv.h"
#include "lldp.h"
#include "macro.h"
#include "string-util.h"

#define TEST_LLDP_PORT "em1"
#define TEST_LLDP_TYPE_SYSTEM_NAME "systemd-lldp"
#define TEST_LLDP_TYPE_SYSTEM_DESC "systemd-lldp-desc"

static int test_fd[2];

static struct ether_addr mac_addr = {
        .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
};

static int lldp_build_tlv_packet(tlv_packet **ret) {
        _cleanup_lldp_packet_unref_ tlv_packet *m = NULL;
        const uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
        struct ether_header ether = {
                .ether_type = htons(ETHERTYPE_LLDP),
        };

        /* Append Ethernet header */
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

static int lldp_get_destination_type(tlv_packet *m) {
        int dest;

        assert_se(sd_lldp_packet_get_destination_type(m, &dest) >= 0);
        assert_se(dest == SD_LLDP_DESTINATION_TYPE_NEAREST_BRIDGE);

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

        assert_se(lldp_get_destination_type(m) >= 0);

        return 0;
}

static void test_parser(void) {
        _cleanup_lldp_packet_unref_ tlv_packet *tlv = NULL;

        /* form a packet */
        lldp_build_tlv_packet(&tlv);
        /* parse the packet */
        tlv_packet_parse_pdu(tlv, tlv->length);
        /* verify */
        lldp_parse_tlv_packet(tlv, tlv->length);
}

int lldp_network_bind_raw_socket(int ifindex) {
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

static int lldp_handler_calls;
static void lldp_handler (sd_lldp *lldp, int event, void *userdata) {
        lldp_handler_calls++;
}

static int start_lldp(sd_lldp **lldp, sd_event *e, sd_lldp_cb_t cb, void *cb_data) {
        int r;

        r = sd_lldp_new(42, "dummy", &mac_addr, lldp);
        if (r)
                return r;

        r = sd_lldp_attach_event(*lldp, e, 0);
        if (r)
                return r;

        r = sd_lldp_set_callback(*lldp, cb, cb_data);
        if (r)
                return r;

        r = sd_lldp_start(*lldp);
        if (r)
                return r;

        return 0;
}

static int stop_lldp(sd_lldp *lldp) {
        int r;

        r = sd_lldp_stop(lldp);
        if (r)
                return r;

        r = sd_lldp_detach_event(lldp);
        if (r)
                return r;

        sd_lldp_free(lldp);
        safe_close(test_fd[1]);

        return 0;
}

static void test_receive_basic_packet(sd_event *e) {
        sd_lldp *lldp;
        sd_lldp_packet **packets;
        uint8_t type, *data;
        uint16_t length, ttl;
        int dest_type;
        char *str;
        uint8_t frame[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC*/
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x07, 0x04, 0x00, 0x01, 0x02,     /* Chassis: MAC, 00:01:02:03:04:05 */
                0x03, 0x04, 0x05,
                0x04, 0x04, 0x05, 0x31, 0x2f, 0x33,     /* Port: interface name, "1/3" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds*/
                /* LLDP optional TLVs */
                0x08, 0x04, 0x50, 0x6f, 0x72, 0x74,     /* Port Description: "Port" */
                0x0a, 0x03, 0x53, 0x59, 0x53,           /* System Name: "SYS" */
                0x0c, 0x04, 0x66, 0x6f, 0x6f, 0x00,     /* System Description: "foo" (NULL-terminated) */
                0x00, 0x00                              /* End Of LLDPDU */
        };

        lldp_handler_calls = 0;
        assert_se(start_lldp(&lldp, e, lldp_handler, NULL) == 0);

        assert_se(write(test_fd[1], frame, sizeof(frame)) == sizeof(frame));
        sd_event_run(e, 0);
        assert_se(lldp_handler_calls == 1);
        assert_se(sd_lldp_get_packets(lldp, &packets) == 1);

        assert_se(sd_lldp_packet_read_chassis_id(packets[0], &type, &data, &length) == 0);
        assert_se(type == LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS);
        assert_se(length == ETH_ALEN);
        assert_se(!memcmp(data, "\x00\x01\x02\x03\x04\x05", ETH_ALEN));

        assert_se(sd_lldp_packet_read_port_id(packets[0], &type, &data, &length) == 0);
        assert_se(type == LLDP_PORT_SUBTYPE_INTERFACE_NAME);
        assert_se(length == 3);
        assert_se(strneq((char *) data, "1/3", 3));

        assert_se(sd_lldp_packet_read_port_description(packets[0], &str, &length) == 0);
        assert_se(length == 4);
        assert_se(strneq(str, "Port", 4));

        assert_se(sd_lldp_packet_read_system_name(packets[0], &str, &length) == 0);
        assert_se(length == 3);
        assert_se(strneq(str, "SYS", 3));

        assert_se(sd_lldp_packet_read_system_description(packets[0], &str, &length) == 0);
        assert_se(length == 4);         /* This is the real length in the TLV packet */
        assert_se(strneq(str, "foo", 3));

        assert_se(sd_lldp_packet_read_ttl(packets[0], &ttl) == 0);
        assert_se(ttl == 120);

        assert_se(sd_lldp_packet_get_destination_type(packets[0], &dest_type) == 0);
        assert_se(dest_type == SD_LLDP_DESTINATION_TYPE_NEAREST_NON_TPMR_BRIDGE);

        sd_lldp_packet_unref(packets[0]);
        free(packets);

        assert_se(stop_lldp(lldp) == 0);
}

static void test_receive_incomplete_packet(sd_event *e) {
        sd_lldp *lldp;
        sd_lldp_packet **packets;
        uint8_t frame[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC*/
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x07, 0x04, 0x00, 0x01, 0x02,     /* Chassis: MAC, 00:01:02:03:04:05 */
                0x03, 0x04, 0x05,
                0x04, 0x04, 0x05, 0x31, 0x2f, 0x33,     /* Port: interface name, "1/3" */
                                                        /* Missing TTL */
                0x00, 0x00                              /* End Of LLDPDU */
        };

        lldp_handler_calls = 0;
        assert_se(start_lldp(&lldp, e, lldp_handler, NULL) == 0);

        assert_se(write(test_fd[1], frame, sizeof(frame)) == sizeof(frame));
        sd_event_run(e, 0);
        assert_se(lldp_handler_calls == 0);
        assert_se(sd_lldp_get_packets(lldp, &packets) == 0);

        assert_se(stop_lldp(lldp) == 0);
}

static void test_receive_oui_packet(sd_event *e) {
        sd_lldp *lldp;
        sd_lldp_packet **packets;
        uint32_t id32;
        uint16_t id16, len;
        uint8_t flags;
        char *str;
        uint8_t frame[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC*/
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x07, 0x04, 0x00, 0x01, 0x02,     /* Chassis: MAC, 00:01:02:03:04:05 */
                0x03, 0x04, 0x05,
                0x04, 0x04, 0x05, 0x31, 0x2f, 0x33,     /* Port TLV: interface name, "1/3" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds*/
                /* LLDP optional TLVs */
                0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01,     /* Port VLAN ID: 0x1234 */
                0x12, 0x34,
                0xfe, 0x07, 0x00, 0x80, 0xc2, 0x02,     /* Port and protocol: flag 1, PPVID 0x7788 */
                0x01, 0x77, 0x88,
                0xfe, 0x0d, 0x00, 0x80, 0xc2, 0x03,     /* VLAN Name: ID 0x1234, name "Vlan51" */
                0x12, 0x34, 0x06, 0x56, 0x6c, 0x61,
                0x6e, 0x35, 0x31,
                0xfe, 0x06, 0x00, 0x80, 0xc2, 0x06,     /* Management VID: 0x0102 */
                0x01, 0x02,
                0xfe, 0x09, 0x00, 0x80, 0xc2, 0x07,     /* Link aggregation: status 1, ID 0x00140012 */
                0x01, 0x00, 0x14, 0x00, 0x12,
                0x00, 0x00                              /* End of LLDPDU */
        };

        lldp_handler_calls = 0;
        assert_se(start_lldp(&lldp, e, lldp_handler, NULL) == 0);

        assert_se(write(test_fd[1], frame, sizeof(frame)) == sizeof(frame));
        sd_event_run(e, 0);
        assert_se(lldp_handler_calls == 1);
        assert_se(sd_lldp_get_packets(lldp, &packets) == 1);

        assert_se(sd_lldp_packet_read_port_vlan_id(packets[0], &id16) == 0);
        assert_se(id16 == 0x1234);

        assert_se(sd_lldp_packet_read_port_protocol_vlan_id(packets[0], &flags, &id16) == 0);
        assert_se(flags == 1);
        assert_se(id16 == 0x7788);

        assert_se(sd_lldp_packet_read_vlan_name(packets[0], &id16, &str, &len) == 0);
        assert_se(id16 == 0x1234);
        assert_se(len == 6);
        assert_se(strneq(str, "Vlan51", 6));

        assert_se(sd_lldp_packet_read_management_vid(packets[0], &id16) == 0);
        assert_se(id16 == 0x0102);

        assert_se(sd_lldp_packet_read_link_aggregation(packets[0], &flags, &id32) == 0);
        assert_se(flags == 1);
        assert_se(id32 == 0x00140012);

        sd_lldp_packet_unref(packets[0]);
        free(packets);

        assert_se(stop_lldp(lldp) == 0);
}

int main(int argc, char *argv[]) {
        _cleanup_event_unref_ sd_event *e = NULL;

        test_parser();

        /* LLDP reception tests */
        assert_se(sd_event_new(&e) == 0);
        test_receive_basic_packet(e);
        test_receive_incomplete_packet(e);
        test_receive_oui_packet(e);

        return 0;
}
