#ifndef foosddhcpclienthfoo
#define foosddhcpclienthfoo

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

#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "sd-dhcp-lease.h"
#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

enum {
        SD_DHCP_CLIENT_EVENT_STOP               = 0,
        SD_DHCP_CLIENT_EVENT_IP_ACQUIRE         = 1,
        SD_DHCP_CLIENT_EVENT_IP_CHANGE          = 2,
        SD_DHCP_CLIENT_EVENT_EXPIRED            = 3,
        SD_DHCP_CLIENT_EVENT_RENEW              = 4,
};

enum {
        SD_DHCP_OPTION_PAD                         = 0,
        SD_DHCP_OPTION_SUBNET_MASK                 = 1,
        SD_DHCP_OPTION_TIME_OFFSET                 = 2,
        SD_DHCP_OPTION_ROUTER                      = 3,
        SD_DHCP_OPTION_DOMAIN_NAME_SERVER          = 6,
        SD_DHCP_OPTION_HOST_NAME                   = 12,
        SD_DHCP_OPTION_BOOT_FILE_SIZE              = 13,
        SD_DHCP_OPTION_DOMAIN_NAME                 = 15,
        SD_DHCP_OPTION_ROOT_PATH                   = 17,
        SD_DHCP_OPTION_ENABLE_IP_FORWARDING        = 19,
        SD_DHCP_OPTION_ENABLE_IP_FORWARDING_NL     = 20,
        SD_DHCP_OPTION_POLICY_FILTER               = 21,
        SD_DHCP_OPTION_INTERFACE_MDR               = 22,
        SD_DHCP_OPTION_INTERFACE_TTL               = 23,
        SD_DHCP_OPTION_INTERFACE_MTU_AGING_TIMEOUT = 24,
        SD_DHCP_OPTION_INTERFACE_MTU               = 26,
        SD_DHCP_OPTION_BROADCAST                   = 28,
        SD_DHCP_OPTION_STATIC_ROUTE                = 33,
        SD_DHCP_OPTION_NTP_SERVER                  = 42,
        SD_DHCP_OPTION_VENDOR_SPECIFIC             = 43,
        SD_DHCP_OPTION_REQUESTED_IP_ADDRESS        = 50,
        SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME       = 51,
        SD_DHCP_OPTION_OVERLOAD                    = 52,
        SD_DHCP_OPTION_MESSAGE_TYPE                = 53,
        SD_DHCP_OPTION_SERVER_IDENTIFIER           = 54,
        SD_DHCP_OPTION_PARAMETER_REQUEST_LIST      = 55,
        SD_DHCP_OPTION_ERROR_MESSAGE               = 56,
        SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE        = 57,
        SD_DHCP_OPTION_RENEWAL_T1_TIME             = 58,
        SD_DHCP_OPTION_REBINDING_T2_TIME           = 59,
        SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER     = 60,
        SD_DHCP_OPTION_CLIENT_IDENTIFIER           = 61,
        SD_DHCP_OPTION_FQDN                        = 81,
        SD_DHCP_OPTION_NEW_POSIX_TIMEZONE          = 100,
        SD_DHCP_OPTION_NEW_TZDB_TIMEZONE           = 101,
        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE      = 121,
        SD_DHCP_OPTION_PRIVATE_BASE                = 224,
        SD_DHCP_OPTION_PRIVATE_LAST                = 254,
        SD_DHCP_OPTION_END                         = 255,
};

typedef struct sd_dhcp_client sd_dhcp_client;

typedef void (*sd_dhcp_client_callback_t)(sd_dhcp_client *client, int event,
                                    void *userdata);
int sd_dhcp_client_set_callback(sd_dhcp_client *client, sd_dhcp_client_callback_t cb,
                                void *userdata);

int sd_dhcp_client_set_request_option(sd_dhcp_client *client, uint8_t option);
int sd_dhcp_client_set_request_address(sd_dhcp_client *client,
                                       const struct in_addr *last_address);
int sd_dhcp_client_set_request_broadcast(sd_dhcp_client *client, int broadcast);
int sd_dhcp_client_set_index(sd_dhcp_client *client, int interface_index);
int sd_dhcp_client_set_mac(sd_dhcp_client *client, const uint8_t *addr,
                           size_t addr_len, uint16_t arp_type);
int sd_dhcp_client_set_client_id(sd_dhcp_client *client, uint8_t type,
                                 const uint8_t *data, size_t data_len);
int sd_dhcp_client_set_iaid_duid(sd_dhcp_client *client, uint32_t iaid,
                                 uint16_t duid_type, uint8_t *duid, size_t duid_len);
int sd_dhcp_client_get_client_id(sd_dhcp_client *client, uint8_t *type,
                                 const uint8_t **data, size_t *data_len);
int sd_dhcp_client_set_mtu(sd_dhcp_client *client, uint32_t mtu);
int sd_dhcp_client_set_hostname(sd_dhcp_client *client, const char *hostname);
int sd_dhcp_client_set_vendor_class_identifier(sd_dhcp_client *client, const char *vci);
int sd_dhcp_client_get_lease(sd_dhcp_client *client, sd_dhcp_lease **ret);

int sd_dhcp_client_stop(sd_dhcp_client *client);
int sd_dhcp_client_start(sd_dhcp_client *client);

sd_dhcp_client *sd_dhcp_client_ref(sd_dhcp_client *client);
sd_dhcp_client *sd_dhcp_client_unref(sd_dhcp_client *client);

int sd_dhcp_client_new(sd_dhcp_client **ret);

int sd_dhcp_client_attach_event(sd_dhcp_client *client, sd_event *event, int64_t priority);
int sd_dhcp_client_detach_event(sd_dhcp_client *client);
sd_event *sd_dhcp_client_get_event(sd_dhcp_client *client);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_client, sd_dhcp_client_unref);

_SD_END_DECLARATIONS;

#endif
