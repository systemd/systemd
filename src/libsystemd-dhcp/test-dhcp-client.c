/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.

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

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "dhcp-protocol.h"
#include "sd-dhcp-client.h"

static void test_request_basic(void)
{
        sd_dhcp_client *client;

        client = sd_dhcp_client_new();

        assert(client);

        assert(sd_dhcp_client_set_request_option(NULL, 0) == -EINVAL);
        assert(sd_dhcp_client_set_request_address(NULL, NULL) == -EINVAL);
        assert(sd_dhcp_client_set_index(NULL, 0) == -EINVAL);

        assert(sd_dhcp_client_set_index(client, 15) == 0);
        assert(sd_dhcp_client_set_index(client, -42) == -EINVAL);
        assert(sd_dhcp_client_set_index(client, -1) == 0);

        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_SUBNET_MASK) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_ROUTER) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_HOST_NAME) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_DOMAIN_NAME) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_DOMAIN_NAME_SERVER)
                        == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_NTP_SERVER) == -EEXIST);

        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_PAD) == -EINVAL);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_END) == -EINVAL);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_MESSAGE_TYPE) == -EINVAL);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_OVERLOAD) == -EINVAL);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_PARAMETER_REQUEST_LIST)
                        == -EINVAL);

        assert(sd_dhcp_client_set_request_option(client, 33) == 0);
        assert(sd_dhcp_client_set_request_option(client, 33) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client, 44) == 0);
}

static uint16_t client_checksum(void *buf, int len)
{
        uint32_t sum;
        uint16_t *check;
        int i;
        uint8_t *odd;

        sum = 0;
        check = buf;

        for (i = 0; i < len / 2 ; i++)
                sum += check[i];

        if (len & 0x01) {
                odd = buf;
                sum += odd[len];
        }

        return ~((sum & 0xffff) + (sum >> 16));
}

static void test_checksum(void)
{
        uint8_t buf[20] = {
                0x45, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff
        };

        uint8_t check[2] = {
                0x78, 0xae
        };

        uint16_t *val = (uint16_t *)check;

        assert(client_checksum(&buf, 20) == *val);
}

int main(int argc, char *argv[])
{
        test_request_basic();
        test_checksum();

        return 0;
}
