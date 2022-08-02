/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcpclienthfoo
#define foosddhcpclienthfoo

/***
  Copyright © 2013 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdbool.h>

#include "sd-dhcp-lease.h"
#include "sd-dhcp-option.h"
#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

enum {
        SD_DHCP_CLIENT_EVENT_STOP               = 0,
        SD_DHCP_CLIENT_EVENT_IP_ACQUIRE         = 1,
        SD_DHCP_CLIENT_EVENT_IP_CHANGE          = 2,
        SD_DHCP_CLIENT_EVENT_EXPIRED            = 3,
        SD_DHCP_CLIENT_EVENT_RENEW              = 4,
        SD_DHCP_CLIENT_EVENT_SELECTING          = 5,
        SD_DHCP_CLIENT_EVENT_TRANSIENT_FAILURE  = 6 /* Sent when we have not received a reply after the first few attempts.
                                                     * The client may want to start acquiring link-local addresses. */
};

/* https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#options */
enum {
        SD_DHCP_OPTION_PAD                            = 0,   /* [RFC2132] */
        SD_DHCP_OPTION_SUBNET_MASK                    = 1,   /* [RFC2132] */
        SD_DHCP_OPTION_TIME_OFFSET                    = 2,   /* [RFC2132], deprecated by 100 and 101 */
        SD_DHCP_OPTION_ROUTER                         = 3,   /* [RFC2132] */
        SD_DHCP_OPTION_TIME_SERVER                    = 4,   /* [RFC2132] */
        SD_DHCP_OPTION_NAME_SERVER                    = 5,   /* [RFC2132] */
        SD_DHCP_OPTION_DOMAIN_NAME_SERVER             = 6,   /* [RFC2132] */
        SD_DHCP_OPTION_LOG_SERVER                     = 7,   /* [RFC2132] */
        SD_DHCP_OPTION_QUOTES_SERVER                  = 8,   /* [RFC2132] */
        SD_DHCP_OPTION_LPR_SERVER                     = 9,   /* [RFC2132] */
        SD_DHCP_OPTION_IMPRESS_SERVER                 = 10,  /* [RFC2132] */
        SD_DHCP_OPTION_RLP_SERVER                     = 11,  /* [RFC2132] */
        SD_DHCP_OPTION_HOST_NAME                      = 12,  /* [RFC2132] */
        SD_DHCP_OPTION_BOOT_FILE_SIZE                 = 13,  /* [RFC2132] */
        SD_DHCP_OPTION_MERIT_DUMP_FILE                = 14,  /* [RFC2132] */
        SD_DHCP_OPTION_DOMAIN_NAME                    = 15,  /* [RFC2132] */
        SD_DHCP_OPTION_SWAP_SERVER                    = 16,  /* [RFC2132] */
        SD_DHCP_OPTION_ROOT_PATH                      = 17,  /* [RFC2132] */
        SD_DHCP_OPTION_EXTENSION_FILE                 = 18,  /* [RFC2132] */
        SD_DHCP_OPTION_FORWARD                        = 19,  /* [RFC2132] */
        SD_DHCP_OPTION_SOURCE_ROUTE                   = 20,  /* [RFC2132] */
        SD_DHCP_OPTION_POLICY_FILTER                  = 21,  /* [RFC2132] */
        SD_DHCP_OPTION_MAX_DATAGRAM_ASSEMBLY          = 22,  /* [RFC2132] */
        SD_DHCP_OPTION_DEFAULT_IP_TTL                 = 23,  /* [RFC2132] */
        SD_DHCP_OPTION_MTU_TIMEOUT                    = 24,  /* [RFC2132] */
        SD_DHCP_OPTION_MTU_PLATEAU                    = 25,  /* [RFC2132] */
        SD_DHCP_OPTION_MTU_INTERFACE                  = 26,  /* [RFC2132] */
        SD_DHCP_OPTION_MTU_SUBNET                     = 27,  /* [RFC2132] */
        SD_DHCP_OPTION_BROADCAST                      = 28,  /* [RFC2132] */
        SD_DHCP_OPTION_MASK_DISCOVERY                 = 29,  /* [RFC2132] */
        SD_DHCP_OPTION_MASK_SUPPLIER                  = 30,  /* [RFC2132] */
        SD_DHCP_OPTION_ROUTER_DISCOVERY               = 31,  /* [RFC2132] */
        SD_DHCP_OPTION_ROUTER_REQUEST                 = 32,  /* [RFC2132] */
        SD_DHCP_OPTION_STATIC_ROUTE                   = 33,  /* [RFC2132] */
        SD_DHCP_OPTION_TRAILERS                       = 34,  /* [RFC2132] */
        SD_DHCP_OPTION_ARP_TIMEOUT                    = 35,  /* [RFC2132] */
        SD_DHCP_OPTION_ETHERNET                       = 36,  /* [RFC2132] */
        SD_DHCP_OPTION_DEFAULT_TCP_TTL                = 37,  /* [RFC2132] */
        SD_DHCP_OPTION_KEEPALIVE_TIME                 = 38,  /* [RFC2132] */
        SD_DHCP_OPTION_KEEPALIVE_DATA                 = 39,  /* [RFC2132] */
        SD_DHCP_OPTION_NIS_DOMAIN                     = 40,  /* [RFC2132] */
        SD_DHCP_OPTION_NIS_SERVER                     = 41,  /* [RFC2132] */
        SD_DHCP_OPTION_NTP_SERVER                     = 42,  /* [RFC2132] */
        SD_DHCP_OPTION_VENDOR_SPECIFIC                = 43,  /* [RFC2132] */
        SD_DHCP_OPTION_NETBIOS_NAME_SERVER            = 44,  /* [RFC2132] */
        SD_DHCP_OPTION_NETBIOS_DIST_SERVER            = 45,  /* [RFC2132] */
        SD_DHCP_OPTION_NETBIOS_NODE_TYPE              = 46,  /* [RFC2132] */
        SD_DHCP_OPTION_NETBIOS_SCOPE                  = 47,  /* [RFC2132] */
        SD_DHCP_OPTION_X_WINDOW_FONT                  = 48,  /* [RFC2132] */
        SD_DHCP_OPTION_X_WINDOW_MANAGER               = 49,  /* [RFC2132] */
        SD_DHCP_OPTION_REQUESTED_IP_ADDRESS           = 50,  /* [RFC2132] */
        SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME          = 51,  /* [RFC2132] */
        SD_DHCP_OPTION_OVERLOAD                       = 52,  /* [RFC2132] */
        SD_DHCP_OPTION_MESSAGE_TYPE                   = 53,  /* [RFC2132] */
        SD_DHCP_OPTION_SERVER_IDENTIFIER              = 54,  /* [RFC2132] */
        SD_DHCP_OPTION_PARAMETER_REQUEST_LIST         = 55,  /* [RFC2132] */
        SD_DHCP_OPTION_ERROR_MESSAGE                  = 56,  /* [RFC2132] */
        SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE           = 57,  /* [RFC2132] */
        SD_DHCP_OPTION_RENEWAL_TIME                   = 58,  /* [RFC2132] */
        SD_DHCP_OPTION_REBINDING_TIME                 = 59,  /* [RFC2132] */
        SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER        = 60,  /* [RFC2132] */
        SD_DHCP_OPTION_CLIENT_IDENTIFIER              = 61,  /* [RFC2132] */
        SD_DHCP_OPTION_NETWARE_IP_DOMAIN              = 62,  /* [RFC2242] */
        SD_DHCP_OPTION_NETWARE_IP_OPTION              = 63,  /* [RFC2242] */
        SD_DHCP_OPTION_NIS_DOMAIN_NAME                = 64,  /* [RFC2132] */
        SD_DHCP_OPTION_NIS_SERVER_ADDR                = 65,  /* [RFC2132] */
        SD_DHCP_OPTION_BOOT_SERVER_NAME               = 66,  /* [RFC2132] */
        SD_DHCP_OPTION_BOOT_FILENAME                  = 67,  /* [RFC2132] */
        SD_DHCP_OPTION_HOME_AGENT_ADDRESSES           = 68,  /* [RFC2132] */
        SD_DHCP_OPTION_SMTP_SERVER                    = 69,  /* [RFC2132] */
        SD_DHCP_OPTION_POP3_SERVER                    = 70,  /* [RFC2132] */
        SD_DHCP_OPTION_NNTP_SERVER                    = 71,  /* [RFC2132] */
        SD_DHCP_OPTION_WWW_SERVER                     = 72,  /* [RFC2132] */
        SD_DHCP_OPTION_FINGER_SERVER                  = 73,  /* [RFC2132] */
        SD_DHCP_OPTION_IRC_SERVER                     = 74,  /* [RFC2132] */
        SD_DHCP_OPTION_STREETTALK_SERVER              = 75,  /* [RFC2132] */
        SD_DHCP_OPTION_STDA_SERVER                    = 76,  /* [RFC2132] */
        SD_DHCP_OPTION_USER_CLASS                     = 77,  /* [RFC3004] */
        SD_DHCP_OPTION_DIRECTORY_AGENT                = 78,  /* [RFC2610] */
        SD_DHCP_OPTION_SERVICE_SCOPE                  = 79,  /* [RFC2610] */
        SD_DHCP_OPTION_RAPID_COMMIT                   = 80,  /* [RFC4039] */
        SD_DHCP_OPTION_FQDN                           = 81,  /* [RFC4702] */
        SD_DHCP_OPTION_RELAY_AGENT_INFORMATION        = 82,  /* [RFC3046] */
        SD_DHCP_OPTION_ISNS                           = 83,  /* [RFC4174] */
        /* option code 84 is unassigned [RFC3679] */
        SD_DHCP_OPTION_NDS_SERVER                     = 85,  /* [RFC2241] */
        SD_DHCP_OPTION_NDS_TREE_NAME                  = 86,  /* [RFC2241] */
        SD_DHCP_OPTION_NDS_CONTEXT                    = 87,  /* [RFC2241] */
        SD_DHCP_OPTION_BCMCS_CONTROLLER_DOMAIN_NAME   = 88,  /* [RFC4280] */
        SD_DHCP_OPTION_BCMCS_CONTROLLER_ADDRESS       = 89,  /* [RFC4280] */
        SD_DHCP_OPTION_AUTHENTICATION                 = 90,  /* [RFC3118] */
        SD_DHCP_OPTION_CLIENT_LAST_TRANSACTION_TIME   = 91,  /* [RFC4388] */
        SD_DHCP_OPTION_ASSOCIATED_IP                  = 92,  /* [RFC4388] */
        SD_DHCP_OPTION_CLIENT_SYSTEM                  = 93,  /* [RFC4578] */
        SD_DHCP_OPTION_CLIENT_NDI                     = 94,  /* [RFC4578] */
        SD_DHCP_OPTION_LDAP                           = 95,  /* [RFC3679] */
        /* option code 96 is unassigned [RFC3679] */
        SD_DHCP_OPTION_UUID                           = 97,  /* [RFC4578] */
        SD_DHCP_OPTION_USER_AUTHENTICATION            = 98,  /* [RFC2485] */
        SD_DHCP_OPTION_GEOCONF_CIVIC                  = 99,  /* [RFC4776] */
        SD_DHCP_OPTION_POSIX_TIMEZONE                 = 100, /* [RFC4833] */
        SD_DHCP_OPTION_TZDB_TIMEZONE                  = 101, /* [RFC4833] */
        /* option codes 102-107 are unassigned [RFC3679] */
        SD_DHCP_OPTION_IPV6_ONLY_PREFERRED            = 108, /* [RFC8925] */
        SD_DHCP_OPTION_DHCP4O6_SOURCE_ADDRESS         = 109, /* [RFC8539] */
        /* option codes 110-111 are unassigned [RFC3679] */
        SD_DHCP_OPTION_NETINFO_ADDRESS                = 112, /* [RFC3679] */
        SD_DHCP_OPTION_NETINFO_TAG                    = 113, /* [RFC3679] */
        SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL            = 114, /* [RFC8910] */
        /* option code 115 is unassigned [RFC3679] */
        SD_DHCP_OPTION_AUTO_CONFIG                    = 116, /* [RFC2563] */
        SD_DHCP_OPTION_NAME_SERVICE_SEARCH            = 117, /* [RFC2937] */
        SD_DHCP_OPTION_SUBNET_SELECTION               = 118, /* [RFC3011] */
        SD_DHCP_OPTION_DOMAIN_SEARCH                  = 119, /* [RFC3397] */
        SD_DHCP_OPTION_SIP_SERVER                     = 120, /* [RFC3361] */
        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE         = 121, /* [RFC3442] */
        SD_DHCP_OPTION_CABLELABS_CLIENT_CONFIGURATION = 122, /* [RFC3495] */
        SD_DHCP_OPTION_GEOCONF                        = 123, /* [RFC6225] */
        SD_DHCP_OPTION_VENDOR_CLASS                   = 124, /* [RFC3925] */
        SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION    = 125, /* [RFC3925] */
        /* option codes 126-127 are unassigned [RFC3679] */
        /* option codes 128-135 are assigned to use by PXE, but they are vendor specific [RFC4578] */
        SD_DHCP_OPTION_PANA_AGENT                     = 136, /* [RFC5192] */
        SD_DHCP_OPTION_LOST_SERVER_FQDN               = 137, /* [RFC5223] */
        SD_DHCP_OPTION_CAPWAP_AC_ADDRESS              = 138, /* [RFC5417] */
        SD_DHCP_OPTION_MOS_ADDRESS                    = 139, /* [RFC5678] */
        SD_DHCP_OPTION_MOS_FQDN                       = 140, /* [RFC5678] */
        SD_DHCP_OPTION_SIP_SERVICE_DOMAIN             = 141, /* [RFC6011] */
        SD_DHCP_OPTION_ANDSF_ADDRESS                  = 142, /* [RFC6153] */
        SD_DHCP_OPTION_SZTP_REDIRECT                  = 143, /* [RFC8572] */
        SD_DHCP_OPTION_GEOLOC                         = 144, /* [RFC6225] */
        SD_DHCP_OPTION_FORCERENEW_NONCE_CAPABLE       = 145, /* [RFC6704] */
        SD_DHCP_OPTION_RDNSS_SELECTION                = 146, /* [RFC6731] */
        SD_DHCP_OPTION_DOTS_RI                        = 147, /* [RFC8973] */
        SD_DHCP_OPTION_DOTS_ADDRESS                   = 148, /* [RFC8973] */
        /* option code 149 is unassigned [RFC3942] */
        SD_DHCP_OPTION_TFTP_SERVER_ADDRESS            = 150, /* [RFC5859] */
        SD_DHCP_OPTION_STATUS_CODE                    = 151, /* [RFC6926] */
        SD_DHCP_OPTION_BASE_TIME                      = 152, /* [RFC6926] */
        SD_DHCP_OPTION_START_TIME_OF_STATE            = 153, /* [RFC6926] */
        SD_DHCP_OPTION_QUERY_START_TIME               = 154, /* [RFC6926] */
        SD_DHCP_OPTION_QUERY_END_TIME                 = 155, /* [RFC6926] */
        SD_DHCP_OPTION_DHCP_STATE                     = 156, /* [RFC6926] */
        SD_DHCP_OPTION_DATA_SOURCE                    = 157, /* [RFC6926] */
        SD_DHCP_OPTION_PCP_SERVER                     = 158, /* [RFC7291] */
        SD_DHCP_OPTION_PORT_PARAMS                    = 159, /* [RFC7618] */
        /* option code 160 is unassigned [RFC7710][RFC8910] */
        SD_DHCP_OPTION_MUD_URL                        = 161, /* [RFC8520] */
        /* option codes 162-174 are unassigned [RFC3942] */
        /* option codes 175-177 are temporary assigned. */
        /* option codes 178-207 are unassigned [RFC3942] */
        SD_DHCP_OPTION_PXELINUX_MAGIC                 = 208, /* [RFC5071] Deprecated */
        SD_DHCP_OPTION_CONFIGURATION_FILE             = 209, /* [RFC5071] */
        SD_DHCP_OPTION_PATH_PREFIX                    = 210, /* [RFC5071] */
        SD_DHCP_OPTION_REBOOT_TIME                    = 211, /* [RFC5071] */
        SD_DHCP_OPTION_6RD                            = 212, /* [RFC5969] */
        SD_DHCP_OPTION_ACCESS_DOMAIN                  = 213, /* [RFC5986] */
        /* option codes 214-219 are unassigned */
        SD_DHCP_OPTION_SUBNET_ALLOCATION              = 220, /* [RFC6656] */
        SD_DHCP_OPTION_VIRTUAL_SUBNET_SELECTION       = 221, /* [RFC6607] */
        /* option codes 222-223 are unassigned [RFC3942] */
        /* option codes 224-254 are reserved for private use */
        SD_DHCP_OPTION_PRIVATE_BASE                   = 224,
        SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE = 249, /* [RFC7844] */
        SD_DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY    = 252, /* [RFC7844] */
        SD_DHCP_OPTION_PRIVATE_LAST                   = 254,
        SD_DHCP_OPTION_END                            = 255 /* [RFC2132] */
};

/* Suboptions for SD_DHCP_OPTION_RELAY_AGENT_INFORMATION option */
enum {
        SD_DHCP_RELAY_AGENT_CIRCUIT_ID             = 1,
        SD_DHCP_RELAY_AGENT_REMOTE_ID              = 2
};

typedef struct sd_dhcp_client sd_dhcp_client;

typedef int (*sd_dhcp_client_callback_t)(sd_dhcp_client *client, int event, void *userdata);
int sd_dhcp_client_set_callback(
                sd_dhcp_client *client,
                sd_dhcp_client_callback_t cb,
                void *userdata);

int sd_dhcp_client_set_request_option(
                sd_dhcp_client *client,
                uint8_t option);
int sd_dhcp_client_set_request_address(
                sd_dhcp_client *client,
                const struct in_addr *last_address);
int sd_dhcp_client_set_request_broadcast(
                sd_dhcp_client *client,
                int broadcast);
int sd_dhcp_client_set_ifindex(
                sd_dhcp_client *client,
                int interface_index);
int sd_dhcp_client_set_ifname(
                sd_dhcp_client *client,
                const char *interface_name);
int sd_dhcp_client_get_ifname(sd_dhcp_client *client, const char **ret);
int sd_dhcp_client_set_mac(
                sd_dhcp_client *client,
                const uint8_t *hw_addr,
                const uint8_t *bcast_addr,
                size_t addr_len,
                uint16_t arp_type);
int sd_dhcp_client_set_client_id(
                sd_dhcp_client *client,
                uint8_t type,
                const uint8_t *data,
                size_t data_len);
__extension__ int sd_dhcp_client_set_iaid_duid(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid,
                uint16_t duid_type,
                const void *duid,
                size_t duid_len);
__extension__ int sd_dhcp_client_set_iaid_duid_llt(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid,
                uint64_t llt_time);
int sd_dhcp_client_set_duid(
                sd_dhcp_client *client,
                uint16_t duid_type,
                const void *duid,
                size_t duid_len);
int sd_dhcp_client_set_duid_llt(
                sd_dhcp_client *client,
                uint64_t llt_time);
int sd_dhcp_client_get_client_id(
                sd_dhcp_client *client,
                uint8_t *type,
                const uint8_t **data,
                size_t *data_len);
int sd_dhcp_client_set_mtu(
                sd_dhcp_client *client,
                uint32_t mtu);
int sd_dhcp_client_set_max_attempts(
                sd_dhcp_client *client,
                uint64_t attempt);
int sd_dhcp_client_set_client_port(
                sd_dhcp_client *client,
                uint16_t port);
int sd_dhcp_client_set_hostname(
                sd_dhcp_client *client,
                const char *hostname);
int sd_dhcp_client_set_vendor_class_identifier(
                sd_dhcp_client *client,
                const char *vci);
int sd_dhcp_client_set_mud_url(
                sd_dhcp_client *client,
                const char *mudurl);
int sd_dhcp_client_set_user_class(
                sd_dhcp_client *client,
                char * const *user_class);
int sd_dhcp_client_get_lease(
                sd_dhcp_client *client,
                sd_dhcp_lease **ret);
int sd_dhcp_client_set_service_type(
                sd_dhcp_client *client,
                int type);
int sd_dhcp_client_set_fallback_lease_lifetime(
                sd_dhcp_client *client,
                uint32_t fallback_lease_lifetime);

int sd_dhcp_client_add_option(sd_dhcp_client *client, sd_dhcp_option *v);
int sd_dhcp_client_add_vendor_option(sd_dhcp_client *client, sd_dhcp_option *v);

int sd_dhcp_client_is_running(sd_dhcp_client *client);
int sd_dhcp_client_stop(sd_dhcp_client *client);
int sd_dhcp_client_start(sd_dhcp_client *client);
int sd_dhcp_client_send_release(sd_dhcp_client *client);
int sd_dhcp_client_send_decline(sd_dhcp_client *client);
int sd_dhcp_client_send_renew(sd_dhcp_client *client);

sd_dhcp_client *sd_dhcp_client_ref(sd_dhcp_client *client);
sd_dhcp_client *sd_dhcp_client_unref(sd_dhcp_client *client);

/* NOTE: anonymize parameter is used to initialize PRL memory with different
 * options when using RFC7844 Anonymity Profiles */
int sd_dhcp_client_new(sd_dhcp_client **ret, int anonymize);

int sd_dhcp_client_id_to_string(const void *data, size_t len, char **ret);

int sd_dhcp_client_attach_event(
                sd_dhcp_client *client,
                sd_event *event,
                int64_t priority);
int sd_dhcp_client_detach_event(sd_dhcp_client *client);
sd_event *sd_dhcp_client_get_event(sd_dhcp_client *client);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_client, sd_dhcp_client_unref);

_SD_END_DECLARATIONS;

#endif
