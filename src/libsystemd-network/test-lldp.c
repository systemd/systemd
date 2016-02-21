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
#include <unistd.h>

#include "sd-event.h"
#include "sd-lldp.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "lldp-network.h"
#include "lldp.h"
#include "macro.h"
#include "string-util.h"

#define TEST_LLDP_PORT "em1"
#define TEST_LLDP_TYPE_SYSTEM_NAME "systemd-lldp"
#define TEST_LLDP_TYPE_SYSTEM_DESC "systemd-lldp-desc"

static int test_fd[2] = { -1, -1 };
static int lldp_handler_calls;

int lldp_network_bind_raw_socket(int ifindex) {
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

static void lldp_handler(sd_lldp *lldp, sd_lldp_event event, sd_lldp_neighbor *n, void *userdata) {
        lldp_handler_calls++;
}

static int start_lldp(sd_lldp **lldp, sd_event *e, sd_lldp_callback_t cb, void *cb_data) {
        int r;

        r = sd_lldp_new(lldp, 42);
        if (r < 0)
                return r;

        r = sd_lldp_attach_event(*lldp, e, 0);
        if (r < 0)
                return r;

        r = sd_lldp_set_callback(*lldp, cb, cb_data);
        if (r < 0)
                return r;

        r = sd_lldp_start(*lldp);
        if (r < 0)
                return r;

        return 0;
}

static int stop_lldp(sd_lldp *lldp) {
        int r;

        r = sd_lldp_stop(lldp);
        if (r < 0)
                return r;

        r = sd_lldp_detach_event(lldp);
        if (r < 0)
                return r;

        sd_lldp_unref(lldp);
        safe_close(test_fd[1]);

        return 0;
}

static void test_receive_basic_packet(sd_event *e) {

        static const uint8_t frame[] = {
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

        sd_lldp *lldp;
        sd_lldp_neighbor **neighbors;
        uint8_t type;
        const void *data;
        uint16_t ttl;
        size_t length;
        const char *str;

        lldp_handler_calls = 0;
        assert_se(start_lldp(&lldp, e, lldp_handler, NULL) == 0);

        assert_se(write(test_fd[1], frame, sizeof(frame)) == sizeof(frame));
        sd_event_run(e, 0);
        assert_se(lldp_handler_calls == 1);
        assert_se(sd_lldp_get_neighbors(lldp, &neighbors) == 1);

        assert_se(sd_lldp_neighbor_get_chassis_id(neighbors[0], &type, &data, &length) == 0);
        assert_se(type == LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS);
        assert_se(length == ETH_ALEN);
        assert_se(!memcmp(data, "\x00\x01\x02\x03\x04\x05", ETH_ALEN));

        assert_se(sd_lldp_neighbor_get_port_id(neighbors[0], &type, &data, &length) == 0);
        assert_se(type == LLDP_PORT_SUBTYPE_INTERFACE_NAME);
        assert_se(length == 3);
        assert_se(strneq((char *) data, "1/3", 3));

        assert_se(sd_lldp_neighbor_get_port_description(neighbors[0], &str) == 0);
        assert_se(streq(str, "Port"));

        assert_se(sd_lldp_neighbor_get_system_name(neighbors[0], &str) == 0);
        assert_se(streq(str, "SYS"));

        assert_se(sd_lldp_neighbor_get_system_description(neighbors[0], &str) == 0);
        assert_se(streq(str, "foo"));

        assert_se(sd_lldp_neighbor_get_ttl(neighbors[0], &ttl) == 0);
        assert_se(ttl == 120);

        sd_lldp_neighbor_unref(neighbors[0]);
        free(neighbors);

        assert_se(stop_lldp(lldp) == 0);
}

static void test_receive_incomplete_packet(sd_event *e) {
        sd_lldp *lldp;
        sd_lldp_neighbor **neighbors;
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
        assert_se(sd_lldp_get_neighbors(lldp, &neighbors) == 0);

        assert_se(stop_lldp(lldp) == 0);
}

static void test_receive_oui_packet(sd_event *e) {
        sd_lldp *lldp;
        sd_lldp_neighbor **neighbors;
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
        assert_se(sd_lldp_get_neighbors(lldp, &neighbors) == 1);

        assert_se(sd_lldp_neighbor_tlv_rewind(neighbors[0]) >= 0);
        assert_se(sd_lldp_neighbor_tlv_is_type(neighbors[0], LLDP_TYPE_CHASSIS_ID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_type(neighbors[0], LLDP_TYPE_PORT_ID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_type(neighbors[0], LLDP_TYPE_TTL) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], LLDP_OUI_802_1, LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], LLDP_OUI_802_1, LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], LLDP_OUI_802_1, LLDP_OUI_802_1_SUBTYPE_VLAN_NAME) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], LLDP_OUI_802_1, LLDP_OUI_802_1_SUBTYPE_MANAGEMENT_VID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], LLDP_OUI_802_1, LLDP_OUI_802_1_SUBTYPE_LINK_AGGREGATION) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_type(neighbors[0], LLDP_TYPE_END) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) == 0);

        sd_lldp_neighbor_unref(neighbors[0]);
        free(neighbors);

        assert_se(stop_lldp(lldp) == 0);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        log_set_max_level(LOG_DEBUG);

        /* LLDP reception tests */
        assert_se(sd_event_new(&e) == 0);
        test_receive_basic_packet(e);
        test_receive_incomplete_packet(e);
        test_receive_oui_packet(e);

        return 0;
}
