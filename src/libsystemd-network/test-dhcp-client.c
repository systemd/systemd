/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-dhcp-client.h"
#include "sd-dhcp-lease.h"
#include "sd-event.h"

#include "dhcp-duid-internal.h"
#include "dhcp-network.h"
#include "dhcp-option.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "log.h"
#include "tests.h"

static struct hw_addr_data hw_addr = {
        .length = ETH_ALEN,
        .ether = {{ 'A', 'B', 'C', '1', '2', '3' }},
}, bcast_addr = {
        .length = ETH_ALEN,
        .ether = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }},
};
typedef void (*test_callback_recv_t)(size_t size, DHCPMessage *dhcp);

struct bootp_addr_data {
        uint8_t *offer_buf;
        size_t offer_len;
        int netmask_offset;
        int ip_offset;
};
static struct bootp_addr_data *bootp_test_context;

static int test_fd[2];
static test_callback_recv_t callback_recv;
static be32_t xid;

TEST(dhcp_client_setters) {
        /* Initialize client without Anonymize settings. */
        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        ASSERT_OK(sd_dhcp_client_new(&client, /* anonymize= */ false));
        ASSERT_NOT_NULL(client);

        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_request_option(NULL, 0) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_request_address(NULL, NULL) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_ifindex(NULL, 0) == -EINVAL);

        ASSERT_OK(sd_dhcp_client_set_ifindex(client, 15));
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_ifindex(client, -42) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_ifindex(client, -1) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_dhcp_client_set_ifindex(client, 0) == -EINVAL);
        ASSERT_OK(sd_dhcp_client_set_ifindex(client, 1));

        ASSERT_OK_POSITIVE(sd_dhcp_client_set_hostname(client, "host"));
        ASSERT_OK_ZERO(sd_dhcp_client_set_hostname(client, "host"));
        ASSERT_OK_POSITIVE(sd_dhcp_client_set_hostname(client, "host.domain"));
        ASSERT_OK_POSITIVE(sd_dhcp_client_set_hostname(client, NULL));
        ASSERT_ERROR(sd_dhcp_client_set_hostname(client, "~host"), EINVAL);
        ASSERT_ERROR(sd_dhcp_client_set_hostname(client, "~host.domain"), EINVAL);

        ASSERT_OK_ZERO(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_SUBNET_MASK));
        ASSERT_OK_ZERO(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_ROUTER));
        ASSERT_OK_ZERO(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_HOST_NAME));
        ASSERT_OK_ZERO(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_DOMAIN_NAME));
        ASSERT_OK_ZERO(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_DOMAIN_NAME_SERVER));

        ASSERT_ERROR(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_PAD), EINVAL);
        ASSERT_ERROR(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_END), EINVAL);
        ASSERT_ERROR(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_MESSAGE_TYPE), EINVAL);
        ASSERT_ERROR(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_OVERLOAD), EINVAL);
        ASSERT_ERROR(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST), EINVAL);

        /* RFC7844: option 33 (SD_DHCP_OPTION_STATIC_ROUTE) is set in the
         * default PRL when using Anonymize, so it is changed to other option
         * that is not set by default, to check that it was set successfully.
         * Options not set by default (using or not anonymize) are option 17
         * (SD_DHCP_OPTION_ROOT_PATH) and 42 (SD_DHCP_OPTION_NTP_SERVER) */
        ASSERT_OK_POSITIVE(sd_dhcp_client_set_request_option(client, 17));
        ASSERT_OK_ZERO(sd_dhcp_client_set_request_option(client, 17));
        ASSERT_OK_POSITIVE(sd_dhcp_client_set_request_option(client, 42));
        ASSERT_OK_ZERO(sd_dhcp_client_set_request_option(client, 17));
}

TEST(dhcp_client_anonymize) {
        /* Initialize client with Anonymize settings. */
        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        ASSERT_OK(sd_dhcp_client_new(&client, /* anonymize= */ true));
        ASSERT_NOT_NULL(client);

        ASSERT_OK_ZERO(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_NETBIOS_NAME_SERVER));
        /* This PRL option is not set when using Anonymize */
        ASSERT_OK_POSITIVE(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_HOST_NAME));
        ASSERT_ERROR(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST), EINVAL);

        /* RFC7844: option 101 (SD_DHCP_OPTION_NEW_TZDB_TIMEZONE) is not set in the
         * default PRL when using Anonymize, */
        ASSERT_OK_POSITIVE(sd_dhcp_client_set_request_option(client, 101));
        ASSERT_OK_ZERO(sd_dhcp_client_set_request_option(client, 101));
}

TEST(dhcp_identifier_set_iaid) {
        uint32_t iaid_legacy;
        be32_t iaid;

        ASSERT_OK(dhcp_identifier_set_iaid(NULL, &hw_addr, /* legacy_unstable_byteorder= */ true, &iaid_legacy));
        ASSERT_OK(dhcp_identifier_set_iaid(NULL, &hw_addr, /* legacy_unstable_byteorder= */ false, &iaid));

        /* we expect, that the MAC address was hashed. The legacy value is in native endianness. */
        ASSERT_EQ(iaid_legacy, 0x8dde4ba8u);
        ASSERT_EQ(iaid, htole32(0x8dde4ba8u));
#if __BYTE_ORDER == __LITTLE_ENDIAN
        ASSERT_EQ(iaid, iaid_legacy);
#else
        ASSERT_EQ(iaid, bswap_32(iaid_legacy));
#endif
}

static int check_options(uint8_t code, uint8_t len, const void *option, void *userdata) {
        switch (code) {
        case SD_DHCP_OPTION_CLIENT_IDENTIFIER: {
                sd_dhcp_duid duid;
                uint32_t iaid;

                ASSERT_OK(sd_dhcp_duid_set_en(&duid));
                ASSERT_OK(dhcp_identifier_set_iaid(NULL, &hw_addr, /* legacy_unstable_byteorder= */ true, &iaid));

                ASSERT_EQ(len, 19u);
                ASSERT_EQ(len, sizeof(uint8_t) + sizeof(uint32_t) + duid.size);
                ASSERT_EQ(((uint8_t*) option)[0], 0xff);

                ASSERT_EQ(memcmp((uint8_t*) option + 1, &iaid, sizeof(iaid)), 0);
                ASSERT_EQ(memcmp((uint8_t*) option + 5, &duid.duid, duid.size), 0);
                break;
        }

        default:
                ;
        }

        return 0;
}

int dhcp_network_send_raw_socket(int fd, const union sockaddr_union *link, const struct iovec_wrapper *iovw) {
        uint16_t ip_check, udp_check;

        ASSERT_OK(fd);
        ASSERT_NOT_NULL(iovw);

        _cleanup_(iovec_done) struct iovec iov = {};
        ASSERT_OK(iovw_concat(iovw, &iov));

        size_t len = iov.iov_len;
        ASSERT_GT(len, sizeof(DHCPPacket));

        DHCPPacket *discover = ASSERT_NOT_NULL(iov.iov_base);

        ASSERT_EQ(discover->ip.ttl, IPDEFTTL);
        ASSERT_EQ(discover->ip.protocol, IPPROTO_UDP);
        ASSERT_EQ(discover->ip.saddr, INADDR_ANY);
        ASSERT_EQ(discover->ip.daddr, INADDR_BROADCAST);
        ASSERT_EQ(discover->udp.source, be16toh(DHCP_PORT_CLIENT));
        ASSERT_EQ(discover->udp.dest, be16toh(DHCP_PORT_SERVER));

        ip_check = discover->ip.check;

        discover->ip.ttl = 0;
        discover->ip.check = discover->udp.len;

        udp_check = ~ip_checksum(&discover->ip.ttl, len - 8);
        ASSERT_EQ(udp_check, 0xffff);

        discover->ip.ttl = IPDEFTTL;
        discover->ip.check = ip_check;

        ip_check = ~ip_checksum((uint8_t*) &discover->ip, sizeof(discover->ip));
        ASSERT_EQ(ip_check, 0xffff);

        ASSERT_NE(discover->dhcp.xid, 0u);
        ASSERT_EQ(memcmp(discover->dhcp.chaddr, hw_addr.bytes, hw_addr.length), 0);

        ASSERT_NOT_NULL(callback_recv);
        callback_recv(len - sizeof(struct iphdr) - sizeof(struct udphdr), &discover->dhcp);

        return 0;
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

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd));
        return test_fd[0];
}

int dhcp_network_bind_udp_socket(int ifindex, be32_t address, uint16_t port, int ip_service_type) {
        return ASSERT_OK_ERRNO(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
}

int dhcp_network_send_udp_socket(int fd, be32_t address, uint16_t port, const struct iovec_wrapper *iovw) {
        return 0;
}

static void test_discover_message_verify(size_t size, struct DHCPMessage *dhcp) {
        ASSERT_OK_EQ(dhcp_option_parse(dhcp, size, check_options, NULL, NULL), DHCP_DISCOVER);
        log_debug("  recv DHCP Discover 0x%08x", be32toh(dhcp->xid));
}

TEST(discover_message) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_NOT_NULL(e);

        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        ASSERT_OK(sd_dhcp_client_new(&client, /* anonymize= */ false));
        ASSERT_NOT_NULL(client);

        ASSERT_OK(sd_dhcp_client_attach_event(client, e, /* priority= */ 0));

        ASSERT_OK(sd_dhcp_client_set_ifindex(client, 42));
        ASSERT_OK(sd_dhcp_client_set_mac(client, hw_addr.bytes, bcast_addr.bytes, hw_addr.length, ARPHRD_ETHER));

        ASSERT_OK(sd_dhcp_client_set_request_option(client, 248));

        callback_recv = test_discover_message_verify;

        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_run(e, /* timeout= */ UINT64_MAX));
        ASSERT_OK(sd_dhcp_client_stop(client));
        ASSERT_NULL(client = sd_dhcp_client_unref(client));

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

static int test_addr_acq_acquired(sd_dhcp_client *client, int event, void *userdata) {
        ASSERT_NOT_NULL(client);
        ASSERT_TRUE(IN_SET(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE, SD_DHCP_CLIENT_EVENT_SELECTING));

        sd_dhcp_lease *lease;
        ASSERT_OK(sd_dhcp_client_get_lease(client, &lease));
        ASSERT_NOT_NULL(lease);

        struct in_addr addr;
        ASSERT_OK(sd_dhcp_lease_get_address(lease, &addr));
        ASSERT_EQ(memcmp(&addr.s_addr, &test_addr_acq_ack[44], sizeof(addr.s_addr)), 0);

        ASSERT_OK(sd_dhcp_lease_get_netmask(lease, &addr));
        ASSERT_EQ(memcmp(&addr.s_addr, &test_addr_acq_ack[285], sizeof(addr.s_addr)), 0);

        const struct in_addr *addrs;
        ASSERT_OK_EQ(sd_dhcp_lease_get_router(lease, &addrs), 1);
        ASSERT_EQ(memcmp(&addrs[0].s_addr, &test_addr_acq_ack[308], sizeof(addrs[0].s_addr)), 0);

        log_info("  DHCP address acquired");

        sd_event *e = ASSERT_NOT_NULL(sd_dhcp_client_get_event(client));
        return ASSERT_OK(sd_event_exit(e, 0));
}

static void test_addr_acq_recv_request(size_t size, DHCPMessage *request) {
        uint16_t udp_check = 0;
        uint8_t *msg_bytes = (uint8_t *)request;

        ASSERT_OK_EQ(dhcp_option_parse(request, size, check_options, NULL, NULL), DHCP_REQUEST);
        ASSERT_EQ(request->xid, xid);

        ASSERT_EQ(msg_bytes[size - 1], SD_DHCP_OPTION_END);

        log_info("  recv DHCP Request  0x%08x", be32toh(xid));

        memcpy(&test_addr_acq_ack[26], &udp_check, sizeof(udp_check));
        memcpy(&test_addr_acq_ack[32], &xid, sizeof(xid));
        memcpy(&test_addr_acq_ack[56], hw_addr.bytes, hw_addr.length);

        callback_recv = NULL;

        ASSERT_OK_EQ_ERRNO(write(test_fd[1], test_addr_acq_ack, sizeof(test_addr_acq_ack)),
                           (ssize_t) sizeof(test_addr_acq_ack));

        log_info("  send DHCP Ack");
};

static void test_addr_acq_recv_discover(size_t size, DHCPMessage *discover) {
        uint16_t udp_check = 0;
        uint8_t *msg_bytes = (uint8_t *)discover;

        ASSERT_OK_EQ(dhcp_option_parse(discover, size, check_options, NULL, NULL), DHCP_DISCOVER);

        ASSERT_EQ(msg_bytes[size - 1], SD_DHCP_OPTION_END);

        xid = discover->xid;

        log_info("  recv DHCP Discover 0x%08x", be32toh(xid));

        memcpy(&test_addr_acq_offer[26], &udp_check, sizeof(udp_check));
        memcpy(&test_addr_acq_offer[32], &xid, sizeof(xid));
        memcpy(&test_addr_acq_offer[56], hw_addr.bytes, hw_addr.length);

        callback_recv = test_addr_acq_recv_request;

        ASSERT_OK_EQ_ERRNO(write(test_fd[1], test_addr_acq_offer, sizeof(test_addr_acq_offer)),
                           (ssize_t) sizeof(test_addr_acq_offer));

        log_info("  sent DHCP Offer");
}

TEST(addr_acq) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_NOT_NULL(e);

        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        ASSERT_OK(sd_dhcp_client_new(&client, /* anonymize= */ false));
        ASSERT_NOT_NULL(client);

        ASSERT_OK(sd_dhcp_client_attach_event(client, e, /* priority= */ 0));

        ASSERT_OK(sd_dhcp_client_set_ifindex(client, 42));
        ASSERT_OK(sd_dhcp_client_set_mac(client, hw_addr.bytes, bcast_addr.bytes, hw_addr.length, ARPHRD_ETHER));

        ASSERT_OK(sd_dhcp_client_set_callback(client, test_addr_acq_acquired, NULL));

        callback_recv = test_addr_acq_recv_discover;

        ASSERT_OK(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)));

        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_dhcp_client_set_callback(client, NULL, NULL));
        ASSERT_OK(sd_dhcp_client_stop(client));
        ASSERT_NULL(client = sd_dhcp_client_unref(client));

        test_fd[1] = safe_close(test_fd[1]);
        callback_recv = NULL;
        xid = 0;
}

static uint8_t test_addr_bootp_reply[] = {
        0x45, 0x00, 0x01, 0x40, 0x00, 0x00, 0x40, 0x00,
        0xff, 0x11, 0x70, 0xab, 0x0a, 0x00, 0x00, 0x02,
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

static int test_bootp_acquired(sd_dhcp_client *client, int event, void *userdata) {
        ASSERT_NOT_NULL(client);
        ASSERT_TRUE(IN_SET(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE, SD_DHCP_CLIENT_EVENT_SELECTING));

        sd_dhcp_lease *lease;
        ASSERT_OK(sd_dhcp_client_get_lease(client, &lease));
        ASSERT_NOT_NULL(lease);

        struct in_addr addr;
        ASSERT_OK(sd_dhcp_lease_get_address(lease, &addr));
        ASSERT_EQ(memcmp(&addr.s_addr, &bootp_test_context->offer_buf[bootp_test_context->ip_offset], sizeof(addr.s_addr)), 0);

        ASSERT_OK(sd_dhcp_lease_get_netmask(lease, &addr));
        ASSERT_EQ(memcmp(&addr.s_addr, &bootp_test_context->offer_buf[bootp_test_context->netmask_offset], sizeof(addr.s_addr)), 0);

        log_info("  BOOTP address acquired");

        sd_event *e = ASSERT_NOT_NULL(sd_dhcp_client_get_event(client));
        return ASSERT_OK(sd_event_exit(e, 0));
}

static void test_bootp_recv_request(size_t size, DHCPMessage *request) {
        uint16_t udp_check = 0;

        xid = request->xid;

        log_info("  recv BOOTP Request  0x%08x", be32toh(xid));

        callback_recv = NULL;

        memcpy(&bootp_test_context->offer_buf[26], &udp_check, sizeof(udp_check));
        memcpy(&bootp_test_context->offer_buf[32], &xid, sizeof(xid));
        memcpy(&bootp_test_context->offer_buf[56], hw_addr.bytes, hw_addr.length);

        ASSERT_OK_EQ_ERRNO(write(test_fd[1], bootp_test_context->offer_buf, bootp_test_context->offer_len),
                           (ssize_t) bootp_test_context->offer_len);

        log_info("  sent BOOTP Reply");
};

static void test_bootp_one(void) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_NOT_NULL(e);

        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        ASSERT_OK(sd_dhcp_client_new(&client, /* anonymize= */ false));
        ASSERT_NOT_NULL(client);

        ASSERT_OK(sd_dhcp_client_attach_event(client, e, /* priority= */ 0));

        ASSERT_OK(sd_dhcp_client_set_bootp(client, true));

        ASSERT_OK(sd_dhcp_client_set_ifindex(client, 42));
        ASSERT_OK(sd_dhcp_client_set_mac(client, hw_addr.bytes, bcast_addr.bytes, hw_addr.length, ARPHRD_ETHER));

        ASSERT_OK(sd_dhcp_client_set_callback(client, test_bootp_acquired, NULL));

        callback_recv = test_bootp_recv_request;

        ASSERT_OK(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)));

        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_dhcp_client_set_callback(client, NULL, NULL));
        ASSERT_OK(sd_dhcp_client_stop(client));
        ASSERT_NULL(client = sd_dhcp_client_unref(client));

        test_fd[1] = safe_close(test_fd[1]);
        callback_recv = NULL;
        xid = 0;
}

TEST(bootp) {
        FOREACH_ELEMENT(i, bootp_addr_data) {
                bootp_test_context = i;
                test_bootp_one();
        }
}

static int intro(void) {
        ASSERT_OK_ERRNO(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", /* overwrite= */ true));
        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
