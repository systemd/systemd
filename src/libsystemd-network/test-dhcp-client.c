/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#if HAVE_VALGRIND_VALGRIND_H
#  include <valgrind/valgrind.h>
#endif

#include "sd-dhcp-client.h"
#include "sd-dhcp-lease.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-duid-internal.h"
#include "dhcp-network.h"
#include "dhcp-option.h"
#include "dhcp-packet.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "log.h"
#include "tests.h"

static struct hw_addr_data hw_addr = {
        .length = ETH_ALEN,
        .ether = {{ 'A', 'B', 'C', '1', '2', '3' }},
}, bcast_addr = {
        .length = ETH_ALEN,
        .ether = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }},
};
typedef int (*test_callback_recv_t)(size_t size, DHCPMessage *dhcp);

struct bootp_addr_data {
        uint8_t *offer_buf;
        size_t offer_len;
        int netmask_offset;
        int ip_offset;
};
struct bootp_addr_data *bootp_test_context;

static bool verbose = true;
static int test_fd[2];
static test_callback_recv_t callback_recv;
static be32_t xid;

static void test_request_basic(sd_event *e) {
        int r;

        sd_dhcp_client *client;

        if (verbose)
                log_info("* %s", __func__);

        /* Initialize client without Anonymize settings. */
        r = sd_dhcp_client_new(&client, false);

        assert_se(r >= 0);
        assert_se(client);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert_se(r >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_request_option(NULL, 0) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_request_address(NULL, NULL) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_ifindex(NULL, 0) == -EINVAL);

        assert_se(sd_dhcp_client_set_ifindex(client, 15) == 0);
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_ifindex(client, -42) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_ifindex(client, -1) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_ifindex(client, 0) == -EINVAL);
        assert_se(sd_dhcp_client_set_ifindex(client, 1) == 0);

        assert_se(sd_dhcp_client_set_hostname(client, "host") == 1);
        assert_se(sd_dhcp_client_set_hostname(client, "host.domain") == 1);
        assert_se(sd_dhcp_client_set_hostname(client, NULL) == 1);
        assert_se(sd_dhcp_client_set_hostname(client, "~host") == -EINVAL);
        assert_se(sd_dhcp_client_set_hostname(client, "~host.domain") == -EINVAL);

        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_SUBNET_MASK) == 0);
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_ROUTER) == 0);
        /* This PRL option is not set when using Anonymize, but in this test
         * Anonymize settings are not being used. */
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_HOST_NAME) == 0);
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_DOMAIN_NAME) == 0);
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_DOMAIN_NAME_SERVER) == 0);

        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_PAD) == -EINVAL);
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_END) == -EINVAL);
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_MESSAGE_TYPE) == -EINVAL);
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_OVERLOAD) == -EINVAL);
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST) == -EINVAL);

        /* RFC7844: option 33 (SD_DHCP_OPTION_STATIC_ROUTE) is set in the
         * default PRL when using Anonymize, so it is changed to other option
         * that is not set by default, to check that it was set successfully.
         * Options not set by default (using or not anonymize) are option 17
         * (SD_DHCP_OPTION_ROOT_PATH) and 42 (SD_DHCP_OPTION_NTP_SERVER) */
        assert_se(sd_dhcp_client_set_request_option(client, 17) == 1);
        assert_se(sd_dhcp_client_set_request_option(client, 17) == 0);
        assert_se(sd_dhcp_client_set_request_option(client, 42) == 1);
        assert_se(sd_dhcp_client_set_request_option(client, 17) == 0);

        sd_dhcp_client_unref(client);
}

static void test_request_anonymize(sd_event *e) {
        int r;

        sd_dhcp_client *client;

        if (verbose)
                log_info("* %s", __func__);

        /* Initialize client with Anonymize settings. */
        r = sd_dhcp_client_new(&client, true);

        assert_se(r >= 0);
        assert_se(client);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert_se(r >= 0);

        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_NETBIOS_NAME_SERVER) == 0);
        /* This PRL option is not set when using Anonymize */
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_HOST_NAME) == 1);
        assert_se(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST) == -EINVAL);

        /* RFC7844: option 101 (SD_DHCP_OPTION_NEW_TZDB_TIMEZONE) is not set in the
         * default PRL when using Anonymize, */
        assert_se(sd_dhcp_client_set_request_option(client, 101) == 1);
        assert_se(sd_dhcp_client_set_request_option(client, 101) == 0);

        sd_dhcp_client_unref(client);
}

static void test_checksum(void) {
        uint8_t buf[20] = {
                0x45, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff
        };

        if (verbose)
                log_info("* %s", __func__);

        assert_se(dhcp_packet_checksum((uint8_t*)&buf, 20) == be16toh(0x78ae));
}

static void test_dhcp_identifier_set_iaid(void) {
        uint32_t iaid_legacy;
        be32_t iaid;

        assert_se(dhcp_identifier_set_iaid(NULL, &hw_addr, /* legacy_unstable_byteorder = */ true, &iaid_legacy) >= 0);
        assert_se(dhcp_identifier_set_iaid(NULL, &hw_addr, /* legacy_unstable_byteorder = */ false, &iaid) >= 0);

        /* we expect, that the MAC address was hashed. The legacy value is in native
         * endianness. */
        assert_se(iaid_legacy == 0x8dde4ba8u);
        assert_se(iaid  == htole32(0x8dde4ba8u));
#if __BYTE_ORDER == __LITTLE_ENDIAN
        assert_se(iaid == iaid_legacy);
#else
        assert_se(iaid == bswap_32(iaid_legacy));
#endif
}

static int check_options(uint8_t code, uint8_t len, const void *option, void *userdata) {
        switch (code) {
        case SD_DHCP_OPTION_CLIENT_IDENTIFIER: {
                sd_dhcp_duid duid;
                uint32_t iaid;

                assert_se(sd_dhcp_duid_set_en(&duid) >= 0);
                assert_se(dhcp_identifier_set_iaid(NULL, &hw_addr, /* legacy_unstable_byteorder = */ true, &iaid) >= 0);

                assert_se(len == sizeof(uint8_t) + sizeof(uint32_t) + duid.size);
                assert_se(len == 19);
                assert_se(((uint8_t*) option)[0] == 0xff);

                assert_se(memcmp((uint8_t*) option + 1, &iaid, sizeof(iaid)) == 0);
                assert_se(memcmp((uint8_t*) option + 5, &duid.duid, duid.size) == 0);
                break;
        }

        default:
                ;
        }

        return 0;
}

int dhcp_network_send_raw_socket(int s, const union sockaddr_union *link, const void *packet, size_t len) {
        size_t size;
        _cleanup_free_ DHCPPacket *discover = NULL;
        uint16_t ip_check, udp_check;

        assert_se(s >= 0);
        assert_se(packet);

        size = sizeof(DHCPPacket);
        assert_se(len > size);

        discover = memdup(packet, len);

        assert_se(discover->ip.ttl == IPDEFTTL);
        assert_se(discover->ip.protocol == IPPROTO_UDP);
        assert_se(discover->ip.saddr == INADDR_ANY);
        assert_se(discover->ip.daddr == INADDR_BROADCAST);
        assert_se(discover->udp.source == be16toh(DHCP_PORT_CLIENT));
        assert_se(discover->udp.dest == be16toh(DHCP_PORT_SERVER));

        ip_check = discover->ip.check;

        discover->ip.ttl = 0;
        discover->ip.check = discover->udp.len;

        udp_check = ~dhcp_packet_checksum((uint8_t*)&discover->ip.ttl, len - 8);
        assert_se(udp_check == 0xffff);

        discover->ip.ttl = IPDEFTTL;
        discover->ip.check = ip_check;

        ip_check = ~dhcp_packet_checksum((uint8_t*)&discover->ip, sizeof(discover->ip));
        assert_se(ip_check == 0xffff);

        assert_se(discover->dhcp.xid);
        assert_se(memcmp(discover->dhcp.chaddr, hw_addr.bytes, hw_addr.length) == 0);

        size = len - sizeof(struct iphdr) - sizeof(struct udphdr);

        assert_se(callback_recv);
        callback_recv(size, &discover->dhcp);

        return 575;
}

int dhcp_network_bind_raw_socket(
                int ifindex,
                union sockaddr_union *link,
                uint32_t id,
                const struct hw_addr_data *_hw_addr,
                const struct hw_addr_data *_bcast_addr,
                uint16_t arp_type,
                uint16_t port,
                bool so_priority_set,
                int so_priority) {

        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

int dhcp_network_bind_udp_socket(int ifindex, be32_t address, uint16_t port, int ip_service_type) {
        int fd;

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        return fd;
}

int dhcp_network_send_udp_socket(int s, be32_t address, uint16_t port, const void *packet, size_t len) {
        return 0;
}

static int test_discover_message_verify(size_t size, struct DHCPMessage *dhcp) {
        int res;

        res = dhcp_option_parse(dhcp, size, check_options, NULL, NULL);
        assert_se(res == DHCP_DISCOVER);

        if (verbose)
                log_info("  recv DHCP Discover 0x%08x", be32toh(dhcp->xid));

        return 0;
}

static void test_discover_message(sd_event *e) {
        sd_dhcp_client *client;
        int res, r;

        if (verbose)
                log_info("* %s", __func__);

        r = sd_dhcp_client_new(&client, false);
        assert_se(r >= 0);
        assert_se(client);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert_se(r >= 0);

        assert_se(sd_dhcp_client_set_ifindex(client, 42) >= 0);
        assert_se(sd_dhcp_client_set_mac(client, hw_addr.bytes, bcast_addr.bytes, hw_addr.length, ARPHRD_ETHER) >= 0);

        assert_se(sd_dhcp_client_set_request_option(client, 248) >= 0);

        callback_recv = test_discover_message_verify;

        res = sd_dhcp_client_start(client);

        assert_se(IN_SET(res, 0, -EINPROGRESS));

        sd_event_run(e, UINT64_MAX);

        sd_dhcp_client_stop(client);
        sd_dhcp_client_unref(client);

        test_fd[1] = safe_close(test_fd[1]);

        callback_recv = NULL;
}

static uint8_t test_addr_acq_offer[] = {
        0x45, 0x10, 0x01, 0x48, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x11, 0xb3, 0x84, 0xc0, 0xa8, 0x02, 0x01,
        0xc0, 0xa8, 0x02, 0xbf, 0x00, 0x43, 0x00, 0x44,
        0x01, 0x34, 0x00, 0x00, 0x02, 0x01, 0x06, 0x00,
        0x6f, 0x95, 0x2f, 0x30, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x02, 0xbf,
        0xc0, 0xa8, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x02, 0x36,
        0x04, 0xc0, 0xa8, 0x02, 0x01, 0x33, 0x04, 0x00,
        0x00, 0x02, 0x58, 0x01, 0x04, 0xff, 0xff, 0xff,
        0x00, 0x2a, 0x04, 0xc0, 0xa8, 0x02, 0x01, 0x0f,
        0x09, 0x6c, 0x61, 0x62, 0x2e, 0x69, 0x6e, 0x74,
        0x72, 0x61, 0x03, 0x04, 0xc0, 0xa8, 0x02, 0x01,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static uint8_t test_addr_acq_ack[] = {
        0x45, 0x10, 0x01, 0x48, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x11, 0xb3, 0x84, 0xc0, 0xa8, 0x02, 0x01,
        0xc0, 0xa8, 0x02, 0xbf, 0x00, 0x43, 0x00, 0x44,
        0x01, 0x34, 0x00, 0x00, 0x02, 0x01, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x02, 0xbf,
        0xc0, 0xa8, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x05, 0x36,
        0x04, 0xc0, 0xa8, 0x02, 0x01, 0x33, 0x04, 0x00,
        0x00, 0x02, 0x58, 0x01, 0x04, 0xff, 0xff, 0xff,
        0x00, 0x2a, 0x04, 0xc0, 0xa8, 0x02, 0x01, 0x0f,
        0x09, 0x6c, 0x61, 0x62, 0x2e, 0x69, 0x6e, 0x74,
        0x72, 0x61, 0x03, 0x04, 0xc0, 0xa8, 0x02, 0x01,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static int test_addr_acq_acquired(sd_dhcp_client *client, int event,
                                   void *userdata) {
        sd_event *e = userdata;
        sd_dhcp_lease *lease;
        struct in_addr addr;
        const struct in_addr *addrs;

        assert_se(client);
        assert_se(IN_SET(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE, SD_DHCP_CLIENT_EVENT_SELECTING));

        assert_se(sd_dhcp_client_get_lease(client, &lease) >= 0);
        assert_se(lease);

        assert_se(sd_dhcp_lease_get_address(lease, &addr) >= 0);
        assert_se(memcmp(&addr.s_addr, &test_addr_acq_ack[44],
                      sizeof(addr.s_addr)) == 0);

        assert_se(sd_dhcp_lease_get_netmask(lease, &addr) >= 0);
        assert_se(memcmp(&addr.s_addr, &test_addr_acq_ack[285],
                      sizeof(addr.s_addr)) == 0);

        assert_se(sd_dhcp_lease_get_router(lease, &addrs) == 1);
        assert_se(memcmp(&addrs[0].s_addr, &test_addr_acq_ack[308],
                         sizeof(addrs[0].s_addr)) == 0);

        if (verbose)
                log_info("  DHCP address acquired");

        sd_event_exit(e, 0);

        return 0;
}

static int test_addr_acq_recv_request(size_t size, DHCPMessage *request) {
        uint16_t udp_check = 0;
        uint8_t *msg_bytes = (uint8_t *)request;
        int res;

        res = dhcp_option_parse(request, size, check_options, NULL, NULL);
        assert_se(res == DHCP_REQUEST);
        assert_se(xid == request->xid);

        assert_se(msg_bytes[size - 1] == SD_DHCP_OPTION_END);

        if (verbose)
                log_info("  recv DHCP Request  0x%08x", be32toh(xid));

        memcpy(&test_addr_acq_ack[26], &udp_check, sizeof(udp_check));
        memcpy(&test_addr_acq_ack[32], &xid, sizeof(xid));
        memcpy(&test_addr_acq_ack[56], hw_addr.bytes, hw_addr.length);

        callback_recv = NULL;

        res = write(test_fd[1], test_addr_acq_ack,
                    sizeof(test_addr_acq_ack));
        assert_se(res == sizeof(test_addr_acq_ack));

        if (verbose)
                log_info("  send DHCP Ack");

        return 0;
};

static int test_addr_acq_recv_discover(size_t size, DHCPMessage *discover) {
        uint16_t udp_check = 0;
        uint8_t *msg_bytes = (uint8_t *)discover;
        int res;

        res = dhcp_option_parse(discover, size, check_options, NULL, NULL);
        assert_se(res == DHCP_DISCOVER);

        assert_se(msg_bytes[size - 1] == SD_DHCP_OPTION_END);

        xid = discover->xid;

        if (verbose)
                log_info("  recv DHCP Discover 0x%08x", be32toh(xid));

        memcpy(&test_addr_acq_offer[26], &udp_check, sizeof(udp_check));
        memcpy(&test_addr_acq_offer[32], &xid, sizeof(xid));
        memcpy(&test_addr_acq_offer[56], hw_addr.bytes, hw_addr.length);

        callback_recv = test_addr_acq_recv_request;

        res = write(test_fd[1], test_addr_acq_offer,
                    sizeof(test_addr_acq_offer));
        assert_se(res == sizeof(test_addr_acq_offer));

        if (verbose)
                log_info("  sent DHCP Offer");

        return 0;
}

static void test_addr_acq(sd_event *e) {
        sd_dhcp_client *client;
        int res, r;

        if (verbose)
                log_info("* %s", __func__);

        r = sd_dhcp_client_new(&client, false);
        assert_se(r >= 0);
        assert_se(client);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert_se(r >= 0);

        assert_se(sd_dhcp_client_set_ifindex(client, 42) >= 0);
        assert_se(sd_dhcp_client_set_mac(client, hw_addr.bytes, bcast_addr.bytes, hw_addr.length, ARPHRD_ETHER) >= 0);

        assert_se(sd_dhcp_client_set_callback(client, test_addr_acq_acquired, e) >= 0);

        callback_recv = test_addr_acq_recv_discover;

        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)) >= 0);

        res = sd_dhcp_client_start(client);
        assert_se(IN_SET(res, 0, -EINPROGRESS));

        assert_se(sd_event_loop(e) >= 0);

        assert_se(sd_dhcp_client_set_callback(client, NULL, NULL) >= 0);
        assert_se(sd_dhcp_client_stop(client) >= 0);
        sd_dhcp_client_unref(client);

        test_fd[1] = safe_close(test_fd[1]);

        callback_recv = NULL;
        xid = 0;
}

static uint8_t test_addr_bootp_reply[] = {
        0x45, 0x00, 0x01, 0x48, 0x00, 0x00, 0x40, 0x00,
        0xff, 0x11, 0x70, 0xa3, 0x0a, 0x00, 0x00, 0x02,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x43, 0x00, 0x44,
        0x01, 0x2c, 0x2b, 0x91, 0x02, 0x01, 0x06, 0x00,
        0x69, 0xd3, 0x79, 0x11, 0x17, 0x00, 0x80, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x46, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x2d, 0xf4, 0x1f, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x63, 0x82, 0x53, 0x63, 0x01, 0x04, 0xff, 0x00,
        0x00, 0x00, 0x36, 0x04, 0x0a, 0x00, 0x00, 0x02,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static uint8_t test_addr_bootp_reply_bootpd[] = {
        0x45, 0x00, 0x01, 0x48, 0xbe, 0xad, 0x40, 0x00,
        0x40, 0x11, 0x73, 0x43, 0xc0, 0xa8, 0x43, 0x31,
        0xc0, 0xa8, 0x43, 0x32, 0x00, 0x43, 0x00, 0x44,
        0x01, 0x34, 0x08, 0xfa, 0x02, 0x01, 0x06, 0x00,
        0x82, 0x57, 0xda, 0xf1, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x43, 0x32,
        0xc0, 0xa8, 0x43, 0x31, 0x00, 0x00, 0x00, 0x00,
        0xc2, 0x3e, 0xa5, 0x53, 0x57, 0x72, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x65, 0x62, 0x69, 0x61, 0x6e, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x63, 0x82, 0x53, 0x63, 0x01, 0x04, 0xff, 0xff,
        0xff, 0xf0, 0x03, 0x04, 0xc0, 0xa8, 0x43, 0x31,
        0x06, 0x04, 0x0a, 0x00, 0x01, 0x01, 0x0c, 0x15,
        0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x64,
        0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x74,
        0x72, 0x69, 0x78, 0x69, 0x65, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static struct bootp_addr_data bootp_addr_data[] = {
        {
                .offer_buf = test_addr_bootp_reply,
                .offer_len = sizeof(test_addr_bootp_reply),
                .netmask_offset = 270,
                .ip_offset = 44,
        },
        {
                .offer_buf = test_addr_bootp_reply_bootpd,
                .offer_len = sizeof(test_addr_bootp_reply_bootpd),
                .netmask_offset = 270,
                .ip_offset = 44,
        },
};

static int test_bootp_acquired(sd_dhcp_client *client, int event,
                               void *userdata) {
        sd_dhcp_lease *lease = NULL;
        sd_event *e = userdata;
        struct in_addr addr;

        ASSERT_NOT_NULL(client);
        assert_se(IN_SET(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE, SD_DHCP_CLIENT_EVENT_SELECTING));

        ASSERT_OK(sd_dhcp_client_get_lease(client, &lease));
        ASSERT_NOT_NULL(lease);

        ASSERT_OK(sd_dhcp_lease_get_address(lease, &addr));
        ASSERT_EQ(memcmp(&addr.s_addr, &bootp_test_context->offer_buf[bootp_test_context->ip_offset],
                      sizeof(addr.s_addr)), 0);

        ASSERT_OK(sd_dhcp_lease_get_netmask(lease, &addr));
        ASSERT_EQ(memcmp(&addr.s_addr, &bootp_test_context->offer_buf[bootp_test_context->netmask_offset],
                      sizeof(addr.s_addr)), 0);

        if (verbose)
                log_info("  BOOTP address acquired");

        sd_event_exit(e, 0);

        return 0;
}

static int test_bootp_recv_request(size_t size, DHCPMessage *request) {
        uint16_t udp_check = 0;
        size_t res;

        xid = request->xid;

        if (verbose)
                log_info("  recv BOOTP Request  0x%08x", be32toh(xid));

        callback_recv = NULL;

        memcpy(&bootp_test_context->offer_buf[26], &udp_check, sizeof(udp_check));
        memcpy(&bootp_test_context->offer_buf[32], &xid, sizeof(xid));
        memcpy(&bootp_test_context->offer_buf[56], hw_addr.bytes, hw_addr.length);

        res = write(test_fd[1], bootp_test_context->offer_buf,
                    bootp_test_context->offer_len);
        ASSERT_EQ(res, bootp_test_context->offer_len);

        if (verbose)
                log_info("  sent BOOTP Reply");

        return 0;
};

static void test_acquire_bootp(sd_event *e) {
        sd_dhcp_client *client = NULL;
        int res;

        if (verbose)
                log_info("* %s", __func__);

        ASSERT_OK(sd_dhcp_client_new(&client, false));
        ASSERT_NOT_NULL(client);

        ASSERT_OK(sd_dhcp_client_attach_event(client, e, 0));

        ASSERT_OK(sd_dhcp_client_set_bootp(client, true));

        ASSERT_OK(sd_dhcp_client_set_ifindex(client, 42));
        ASSERT_OK(sd_dhcp_client_set_mac(client, hw_addr.bytes, bcast_addr.bytes, hw_addr.length, ARPHRD_ETHER));

        ASSERT_OK(sd_dhcp_client_set_callback(client, test_bootp_acquired, e));

        callback_recv = test_bootp_recv_request;

        ASSERT_OK(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)));

        res = sd_dhcp_client_start(client);
        assert_se(IN_SET(res, 0, -EINPROGRESS));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_dhcp_client_set_callback(client, NULL, NULL));
        ASSERT_OK(sd_dhcp_client_stop(client));
        client = sd_dhcp_client_unref(client);
        ASSERT_NULL(client);

        test_fd[1] = safe_close(test_fd[1]);

        callback_recv = NULL;
        xid = 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *e;

        assert_se(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", 1) >= 0);

        test_setup_logging(LOG_DEBUG);

        assert_se(sd_event_new(&e) >= 0);

        test_request_basic(e);
        test_request_anonymize(e);
        test_checksum();
        test_dhcp_identifier_set_iaid();

        test_discover_message(e);
        test_addr_acq(e);

        FOREACH_ELEMENT(i, bootp_addr_data) {
                sd_event_unref(e);
                ASSERT_OK(sd_event_new(&e));
                bootp_test_context = i;
                test_acquire_bootp(e);
        }

#if HAVE_VALGRIND_VALGRIND_H
        /* Make sure the async_close thread has finished.
         * valgrind would report some of the phread_* structures
         * as not cleaned up properly. */
        if (RUNNING_ON_VALGRIND)
                sleep(1);
#endif

        return 0;
}
