/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-lldp-rx.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "lldp-network.h"
#include "macro.h"
#include "string-util.h"
#include "tests.h"

#define TEST_LLDP_PORT "em1"
#define TEST_LLDP_TYPE_SYSTEM_NAME "systemd-lldp"
#define TEST_LLDP_TYPE_SYSTEM_DESC "systemd-lldp-desc"

static int test_fd[2] = { -1, -1 };
static int lldp_rx_handler_calls;

int lldp_network_bind_raw_socket(int ifindex) {
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

static void lldp_rx_handler(sd_lldp_rx *lldp_rx, sd_lldp_rx_event_t event, sd_lldp_neighbor *n, void *userdata) {
        lldp_rx_handler_calls++;
}

static int start_lldp_rx(sd_lldp_rx **lldp_rx, sd_event *e, sd_lldp_rx_callback_t cb, void *cb_data) {
        int r;

        r = sd_lldp_rx_new(lldp_rx);
        if (r < 0)
                return r;

        r = sd_lldp_rx_set_ifindex(*lldp_rx, 42);
        if (r < 0)
                return r;

        r = sd_lldp_rx_set_callback(*lldp_rx, cb, cb_data);
        if (r < 0)
                return r;

        r = sd_lldp_rx_attach_event(*lldp_rx, e, 0);
        if (r < 0)
                return r;

        r = sd_lldp_rx_start(*lldp_rx);
        if (r < 0)
                return r;

        return 0;
}

static int stop_lldp_rx(sd_lldp_rx *lldp_rx) {
        int r;

        r = sd_lldp_rx_stop(lldp_rx);
        if (r < 0)
                return r;

        r = sd_lldp_rx_detach_event(lldp_rx);
        if (r < 0)
                return r;

        sd_lldp_rx_unref(lldp_rx);
        safe_close(test_fd[1]);

        return 0;
}

static void test_receive_basic_packet(sd_event *e) {

        static const uint8_t frame[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x07, 0x04, 0x00, 0x01, 0x02,     /* Chassis: MAC, 00:01:02:03:04:05 */
                0x03, 0x04, 0x05,
                0x04, 0x04, 0x05, 0x31, 0x2f, 0x33,     /* Port: interface name, "1/3" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds */
                /* LLDP optional TLVs */
                0x08, 0x04, 0x50, 0x6f, 0x72, 0x74,     /* Port Description: "Port" */
                0x0a, 0x03, 0x53, 0x59, 0x53,           /* System Name: "SYS" */
                0x0c, 0x04, 0x66, 0x6f, 0x6f, 0x00,     /* System Description: "foo" (NULL-terminated) */
                0x00, 0x00                              /* End Of LLDPDU */
        };

        sd_lldp_rx *lldp_rx;
        sd_lldp_neighbor **neighbors;
        uint8_t type;
        const void *data;
        uint16_t ttl;
        size_t length;
        const char *str;

        lldp_rx_handler_calls = 0;
        assert_se(start_lldp_rx(&lldp_rx, e, lldp_rx_handler, NULL) == 0);

        assert_se(write(test_fd[1], frame, sizeof(frame)) == sizeof(frame));
        sd_event_run(e, 0);
        assert_se(lldp_rx_handler_calls == 1);
        assert_se(sd_lldp_rx_get_neighbors(lldp_rx, &neighbors) == 1);

        assert_se(sd_lldp_neighbor_get_chassis_id(neighbors[0], &type, &data, &length) == 0);
        assert_se(type == SD_LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS);
        assert_se(length == ETH_ALEN);
        assert_se(!memcmp(data, "\x00\x01\x02\x03\x04\x05", ETH_ALEN));

        assert_se(sd_lldp_neighbor_get_port_id(neighbors[0], &type, &data, &length) == 0);
        assert_se(type == SD_LLDP_PORT_SUBTYPE_INTERFACE_NAME);
        assert_se(length == 3);
        assert_se(!memcmp(data, "1/3", 3));

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

        assert_se(stop_lldp_rx(lldp_rx) == 0);
}

static void test_receive_incomplete_packet(sd_event *e) {
        sd_lldp_rx *lldp_rx;
        sd_lldp_neighbor **neighbors;
        uint8_t frame[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x07, 0x04, 0x00, 0x01, 0x02,     /* Chassis: MAC, 00:01:02:03:04:05 */
                0x03, 0x04, 0x05,
                0x04, 0x04, 0x05, 0x31, 0x2f, 0x33,     /* Port: interface name, "1/3" */
                                                        /* Missing TTL */
                0x00, 0x00                              /* End Of LLDPDU */
        };

        lldp_rx_handler_calls = 0;
        assert_se(start_lldp_rx(&lldp_rx, e, lldp_rx_handler, NULL) == 0);

        assert_se(write(test_fd[1], frame, sizeof(frame)) == sizeof(frame));
        sd_event_run(e, 0);
        assert_se(lldp_rx_handler_calls == 0);
        assert_se(sd_lldp_rx_get_neighbors(lldp_rx, &neighbors) == 0);

        assert_se(stop_lldp_rx(lldp_rx) == 0);
}

static void test_receive_oui_packet(sd_event *e) {
        sd_lldp_rx *lldp_rx;
        sd_lldp_neighbor **neighbors;
        uint8_t frame[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x07, 0x04, 0x00, 0x01, 0x02,     /* Chassis: MAC, 00:01:02:03:04:05 */
                0x03, 0x04, 0x05,
                0x04, 0x04, 0x05, 0x31, 0x2f, 0x33,     /* Port TLV: interface name, "1/3" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds */
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
                0xfe, 0x07, 0x00, 0x12, 0x0f, 0x02,     /* 802.3 Power via MDI: PSE, MDI enabled */
                0x07, 0x01, 0x00,
                0x00, 0x00                              /* End of LLDPDU */
        };

        lldp_rx_handler_calls = 0;
        assert_se(start_lldp_rx(&lldp_rx, e, lldp_rx_handler, NULL) == 0);

        assert_se(write(test_fd[1], frame, sizeof(frame)) == sizeof(frame));
        sd_event_run(e, 0);
        assert_se(lldp_rx_handler_calls == 1);
        assert_se(sd_lldp_rx_get_neighbors(lldp_rx, &neighbors) == 1);

        assert_se(sd_lldp_neighbor_tlv_rewind(neighbors[0]) >= 0);
        assert_se(sd_lldp_neighbor_tlv_is_type(neighbors[0], SD_LLDP_TYPE_CHASSIS_ID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_type(neighbors[0], SD_LLDP_TYPE_PORT_ID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_type(neighbors[0], SD_LLDP_TYPE_TTL) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], SD_LLDP_OUI_802_1, SD_LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], SD_LLDP_OUI_802_1, SD_LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], SD_LLDP_OUI_802_1, SD_LLDP_OUI_802_1_SUBTYPE_VLAN_NAME) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], SD_LLDP_OUI_802_1, SD_LLDP_OUI_802_1_SUBTYPE_MANAGEMENT_VID) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], SD_LLDP_OUI_802_1, SD_LLDP_OUI_802_1_SUBTYPE_LINK_AGGREGATION) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_oui(neighbors[0], SD_LLDP_OUI_802_3, SD_LLDP_OUI_802_3_SUBTYPE_POWER_VIA_MDI) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) > 0);
        assert_se(sd_lldp_neighbor_tlv_is_type(neighbors[0], SD_LLDP_TYPE_END) > 0);
        assert_se(sd_lldp_neighbor_tlv_next(neighbors[0]) == 0);

        sd_lldp_neighbor_unref(neighbors[0]);
        free(neighbors);

        assert_se(stop_lldp_rx(lldp_rx) == 0);
}

static void test_multiple_neighbors_sorted(sd_event *e) {

        static const uint8_t frame1[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x04, 0x01, '1', '/', '2',        /* Chassis component: "1/2" */
                0x04, 0x04, 0x02, '2', '/', '3',        /* Port component: "2/3" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds */
                0x00, 0x00                              /* End Of LLDPDU */
        };
        static const uint8_t frame2[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x04, 0x01, '2', '/', '1',        /* Chassis component: "2/1" */
                0x04, 0x04, 0x02, '1', '/', '3',        /* Port component: "1/3" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds */
                0x00, 0x00                              /* End Of LLDPDU */
        };
        static const uint8_t frame3[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x05, 0x01, '2', '/', '1', '0',   /* Chassis component: "2/10" */
                0x04, 0x04, 0x02, '1', '/', '0',        /* Port component: "1/0" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds */
                0x00, 0x00                              /* End Of LLDPDU */
        };
        static const uint8_t frame4[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x05, 0x01, '2', '/', '1', '9',   /* Chassis component: "2/19" */
                0x04, 0x04, 0x02, '1', '/', '0',        /* Port component: "1/0" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds */
                0x00, 0x00                              /* End Of LLDPDU */
        };
        static const uint8_t frame5[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x04, 0x01, '1', '/', '2',        /* Chassis component: "1/2" */
                0x04, 0x05, 0x02, '2', '/', '1', '0',   /* Port component: "2/10" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds */
                0x00, 0x00                              /* End Of LLDPDU */
        };
        static const uint8_t frame6[] = {
                /* Ethernet header */
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
                0x88, 0xcc,                             /* Ethertype */
                /* LLDP mandatory TLVs */
                0x02, 0x04, 0x01, '1', '/', '2',        /* Chassis component: "1/2" */
                0x04, 0x05, 0x02, '2', '/', '3', '9',   /* Port component: "2/10" */
                0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds */
                0x00, 0x00                              /* End Of LLDPDU */
        };
        static const char* expected[] = {
                /* ordered pairs of Chassis+Port */
                "1/2", "2/10",
                "1/2", "2/3",
                "1/2", "2/39",
                "2/1", "1/3",
                "2/10", "1/0",
                "2/19", "1/0",
        };

        sd_lldp_rx *lldp_rx;
        sd_lldp_neighbor **neighbors;
        int i;
        uint8_t type;
        const void *data;
        size_t length, expected_length;
        uint16_t ttl;

        lldp_rx_handler_calls = 0;
        assert_se(start_lldp_rx(&lldp_rx, e, lldp_rx_handler, NULL) == 0);

        assert_se(write(test_fd[1], frame1, sizeof(frame1)) == sizeof(frame1));
        sd_event_run(e, 0);
        assert_se(write(test_fd[1], frame2, sizeof(frame2)) == sizeof(frame2));
        sd_event_run(e, 0);
        assert_se(write(test_fd[1], frame3, sizeof(frame3)) == sizeof(frame3));
        sd_event_run(e, 0);
        assert_se(write(test_fd[1], frame4, sizeof(frame4)) == sizeof(frame4));
        sd_event_run(e, 0);
        assert_se(write(test_fd[1], frame5, sizeof(frame5)) == sizeof(frame5));
        sd_event_run(e, 0);
        assert_se(write(test_fd[1], frame6, sizeof(frame6)) == sizeof(frame6));
        sd_event_run(e, 0);
        assert_se(lldp_rx_handler_calls == 6);

        assert_se(sd_lldp_rx_get_neighbors(lldp_rx, &neighbors) == 6);

        for (i = 0; i < 6; i++) {
                assert_se(sd_lldp_neighbor_get_chassis_id(neighbors[i], &type, &data, &length) == 0);
                assert_se(type == SD_LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT);
                expected_length = strlen(expected[2 * i]);
                assert_se(length == expected_length);
                assert_se(memcmp(data, expected[2 * i], expected_length) == 0);

                assert_se(sd_lldp_neighbor_get_port_id(neighbors[i], &type, &data, &length) == 0);
                assert_se(type == SD_LLDP_PORT_SUBTYPE_PORT_COMPONENT);
                expected_length = strlen(expected[2 * i + 1]);
                assert_se(length == expected_length);
                assert_se(memcmp(data, expected[2 * i + 1], expected_length) == 0);

                assert_se(sd_lldp_neighbor_get_ttl(neighbors[i], &ttl) == 0);
                assert_se(ttl == 120);
        }

        for (i = 0; i < 6; i++)
                sd_lldp_neighbor_unref(neighbors[i]);
        free(neighbors);

        assert_se(stop_lldp_rx(lldp_rx) == 0);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        test_setup_logging(LOG_DEBUG);

        /* LLDP reception tests */
        assert_se(sd_event_new(&e) == 0);
        test_receive_basic_packet(e);
        test_receive_incomplete_packet(e);
        test_receive_oui_packet(e);
        test_multiple_neighbors_sorted(e);

        return 0;
}
