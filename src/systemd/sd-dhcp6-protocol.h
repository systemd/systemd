/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcp6protocolhfoo
#define foosddhcp6protocolhfoo

/***
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

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

/* https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#dhcpv6-parameters-2 */
enum {
        SD_DHCP6_OPTION_CLIENTID                   = 1,  /* RFC 8415 */
        SD_DHCP6_OPTION_SERVERID                   = 2,  /* RFC 8415 */
        SD_DHCP6_OPTION_IA_NA                      = 3,  /* RFC 8415 */
        SD_DHCP6_OPTION_IA_TA                      = 4,  /* RFC 8415 */
        SD_DHCP6_OPTION_IAADDR                     = 5,  /* RFC 8415 */
        SD_DHCP6_OPTION_ORO                        = 6,  /* RFC 8415 */
        SD_DHCP6_OPTION_PREFERENCE                 = 7,  /* RFC 8415 */
        SD_DHCP6_OPTION_ELAPSED_TIME               = 8,  /* RFC 8415 */
        SD_DHCP6_OPTION_RELAY_MSG                  = 9,  /* RFC 8415 */
        /* option code 10 is unassigned */
        SD_DHCP6_OPTION_AUTH                       = 11,  /* RFC 8415 */
        SD_DHCP6_OPTION_UNICAST                    = 12,  /* RFC 8415 */
        SD_DHCP6_OPTION_STATUS_CODE                = 13,  /* RFC 8415 */
        SD_DHCP6_OPTION_RAPID_COMMIT               = 14,  /* RFC 8415 */
        SD_DHCP6_OPTION_USER_CLASS                 = 15,  /* RFC 8415 */
        SD_DHCP6_OPTION_VENDOR_CLASS               = 16,  /* RFC 8415 */
        SD_DHCP6_OPTION_VENDOR_OPTS                = 17,  /* RFC 8415 */
        SD_DHCP6_OPTION_INTERFACE_ID               = 18,  /* RFC 8415 */
        SD_DHCP6_OPTION_RECONF_MSG                 = 19,  /* RFC 8415 */
        SD_DHCP6_OPTION_RECONF_ACCEPT              = 20,  /* RFC 8415 */
        SD_DHCP6_OPTION_SIP_SERVER_DOMAIN_NAME     = 21,  /* RFC 3319 */
        SD_DHCP6_OPTION_SIP_SERVER_ADDRESS         = 22,  /* RFC 3319 */
        SD_DHCP6_OPTION_DNS_SERVER                 = 23,  /* RFC 3646 */
        SD_DHCP6_OPTION_DOMAIN                     = 24,  /* RFC 3646 */
        SD_DHCP6_OPTION_IA_PD                      = 25,  /* RFC 3633, RFC 8415 */
        SD_DHCP6_OPTION_IA_PD_PREFIX               = 26,  /* RFC 3633, RFC 8415 */
        SD_DHCP6_OPTION_NIS_SERVER                 = 27,  /* RFC 3898 */
        SD_DHCP6_OPTION_NISP_SERVER                = 28,  /* RFC 3898 */
        SD_DHCP6_OPTION_NIS_DOMAIN_NAME            = 29,  /* RFC 3898 */
        SD_DHCP6_OPTION_NISP_DOMAIN_NAME           = 30,  /* RFC 3898 */
        SD_DHCP6_OPTION_SNTP_SERVER                = 31,  /* RFC 4075, deprecated */
        SD_DHCP6_OPTION_INFORMATION_REFRESH_TIME   = 32,  /* RFC 4242, 8415, sec. 21.23 */
        SD_DHCP6_OPTION_BCMCS_SERVER_D             = 33,  /* RFC 4280 */
        SD_DHCP6_OPTION_BCMCS_SERVER_A             = 34,  /* RFC 4280 */
        /* option code 35 is unassigned */
        SD_DHCP6_OPTION_GEOCONF_CIVIC              = 36,  /* RFC 4776 */
        SD_DHCP6_OPTION_REMOTE_ID                  = 37,  /* RFC 4649 */
        SD_DHCP6_OPTION_SUBSCRIBER_ID              = 38,  /* RFC 4580 */
        SD_DHCP6_OPTION_CLIENT_FQDN                = 39,  /* RFC 4704 */
        SD_DHCP6_OPTION_PANA_AGENT                 = 40,  /* RFC 5192 */
        SD_DHCP6_OPTION_POSIX_TIMEZONE             = 41,  /* RFC 4833 */
        SD_DHCP6_OPTION_TZDB_TIMEZONE              = 42,  /* RFC 4833 */
        SD_DHCP6_OPTION_ERO                        = 43,  /* RFC 4994 */
        SD_DHCP6_OPTION_LQ_QUERY                   = 44,  /* RFC 5007 */
        SD_DHCP6_OPTION_CLIENT_DATA                = 45,  /* RFC 5007 */
        SD_DHCP6_OPTION_CLT_TIME                   = 46,  /* RFC 5007 */
        SD_DHCP6_OPTION_LQ_RELAY_DATA              = 47,  /* RFC 5007 */
        SD_DHCP6_OPTION_LQ_CLIENT_LINK             = 48,  /* RFC 5007 */
        SD_DHCP6_OPTION_MIP6_HNIDF                 = 49,  /* RFC 6610 */
        SD_DHCP6_OPTION_MIP6_VDINF                 = 50,  /* RFC 6610 */
        SD_DHCP6_OPTION_V6_LOST                    = 51,  /* RFC 5223 */
        SD_DHCP6_OPTION_CAPWAP_AC_V6               = 52,  /* RFC 5417 */
        SD_DHCP6_OPTION_RELAY_ID                   = 53,  /* RFC 5460 */
        SD_DHCP6_OPTION_IPV6_ADDRESS_MOS           = 54,  /* RFC 5678 */
        SD_DHCP6_OPTION_IPV6_FQDN_MOS              = 55,  /* RFC 5678 */
        SD_DHCP6_OPTION_NTP_SERVER                 = 56,  /* RFC 5908 */
        SD_DHCP6_OPTION_V6_ACCESS_DOMAIN           = 57,  /* RFC 5986 */
        SD_DHCP6_OPTION_SIP_UA_CS_LIST             = 58,  /* RFC 6011 */
        SD_DHCP6_OPTION_BOOTFILE_URL               = 59,  /* RFC 5970 */
        SD_DHCP6_OPTION_BOOTFILE_PARAM             = 60,  /* RFC 5970 */
        SD_DHCP6_OPTION_CLIENT_ARCH_TYPE           = 61,  /* RFC 5970 */
        SD_DHCP6_OPTION_NII                        = 62,  /* RFC 5970 */
        SD_DHCP6_OPTION_GEOLOCATION                = 63,  /* RFC 6225 */
        SD_DHCP6_OPTION_AFTR_NAME                  = 64,  /* RFC 6334 */
        SD_DHCP6_OPTION_ERP_LOCAL_DOMAIN_NAME      = 65,  /* RFC 6440 */
        SD_DHCP6_OPTION_RSOO                       = 66,  /* RFC 6422 */
        SD_DHCP6_OPTION_PD_EXCLUDE                 = 67,  /* RFC 6603 */
        SD_DHCP6_OPTION_VSS                        = 68,  /* RFC 6607 */
        SD_DHCP6_OPTION_MIP6_IDINF                 = 69,  /* RFC 6610 */
        SD_DHCP6_OPTION_MIP6_UDINF                 = 70,  /* RFC 6610 */
        SD_DHCP6_OPTION_MIP6_HNP                   = 71,  /* RFC 6610 */
        SD_DHCP6_OPTION_MIP6_HAA                   = 72,  /* RFC 6610 */
        SD_DHCP6_OPTION_MIP6_HAF                   = 73,  /* RFC 6610 */
        SD_DHCP6_OPTION_RDNSS_SELECTION            = 74,  /* RFC 6731 */
        SD_DHCP6_OPTION_KRB_PRINCIPAL_NAME         = 75,  /* RFC 6784 */
        SD_DHCP6_OPTION_KRB_REALM_NAME             = 76,  /* RFC 6784 */
        SD_DHCP6_OPTION_KRB_DEFAULT_REALM_NAME     = 77,  /* RFC 6784 */
        SD_DHCP6_OPTION_KRB_KDC                    = 78,  /* RFC 6784 */
        SD_DHCP6_OPTION_CLIENT_LINKLAYER_ADDR      = 79,  /* RFC 6939 */
        SD_DHCP6_OPTION_LINK_ADDRESS               = 80,  /* RFC 6977 */
        SD_DHCP6_OPTION_RADIUS                     = 81,  /* RFC 7037 */
        SD_DHCP6_OPTION_SOL_MAX_RT                 = 82,  /* RFC 7083, RFC 8415 */
        SD_DHCP6_OPTION_INF_MAX_RT                 = 83,  /* RFC 7083, RFC 8415 */
        SD_DHCP6_OPTION_ADDRSEL                    = 84,  /* RFC 7078 */
        SD_DHCP6_OPTION_ADDRSEL_TABLE              = 85,  /* RFC 7078 */
        SD_DHCP6_OPTION_V6_PCP_SERVER              = 86,  /* RFC 7291 */
        SD_DHCP6_OPTION_DHCPV4_MSG                 = 87,  /* RFC 7341 */
        SD_DHCP6_OPTION_DHCP4_O_DHCP6_SERVER       = 88,  /* RFC 7341 */
        SD_DHCP6_OPTION_S46_RULE                   = 89,  /* RFC 7598 */
        SD_DHCP6_OPTION_S46_BR                     = 90,  /* RFC 7598, RFC 8539 */
        SD_DHCP6_OPTION_S46_DMR                    = 91,  /* RFC 7598 */
        SD_DHCP6_OPTION_S46_V4V6BIND               = 92,  /* RFC 7598 */
        SD_DHCP6_OPTION_S46_PORTPARAMS             = 93,  /* RFC 7598 */
        SD_DHCP6_OPTION_S46_CONT_MAPE              = 94,  /* RFC 7598 */
        SD_DHCP6_OPTION_S46_CONT_MAPT              = 95,  /* RFC 7598 */
        SD_DHCP6_OPTION_S46_CONT_LW                = 96,  /* RFC 7598 */
        SD_DHCP6_OPTION_4RD                        = 97,  /* RFC 7600 */
        SD_DHCP6_OPTION_4RD_MAP_RULE               = 98,  /* RFC 7600 */
        SD_DHCP6_OPTION_4RD_NON_MAP_RULE           = 99,  /* RFC 7600 */
        SD_DHCP6_OPTION_LQ_BASE_TIME               = 100, /* RFC 7653 */
        SD_DHCP6_OPTION_LQ_START_TIME              = 101, /* RFC 7653 */
        SD_DHCP6_OPTION_LQ_END_TIME                = 102, /* RFC 7653 */
        SD_DHCP6_OPTION_CAPTIVE_PORTAL             = 103, /* RFC 8910 */
        SD_DHCP6_OPTION_MPL_PARAMETERS             = 104, /* RFC 7774 */
        SD_DHCP6_OPTION_ANI_ATT                    = 105, /* RFC 7839 */
        SD_DHCP6_OPTION_ANI_NETWORK_NAME           = 106, /* RFC 7839 */
        SD_DHCP6_OPTION_ANI_AP_NAME                = 107, /* RFC 7839 */
        SD_DHCP6_OPTION_ANI_AP_BSSID               = 108, /* RFC 7839 */
        SD_DHCP6_OPTION_ANI_OPERATOR_ID            = 109, /* RFC 7839 */
        SD_DHCP6_OPTION_ANI_OPERATOR_REALM         = 110, /* RFC 7839 */
        SD_DHCP6_OPTION_S46_PRIORITY               = 111, /* RFC 8026 */
        SD_DHCP6_OPTION_MUD_URL_V6                 = 112, /* RFC 8520 */
        SD_DHCP6_OPTION_V6_PREFIX64                = 113, /* RFC 8115 */
        SD_DHCP6_OPTION_F_BINDING_STATUS           = 114, /* RFC 8156 */
        SD_DHCP6_OPTION_F_CONNECT_FLAGS            = 115, /* RFC 8156 */
        SD_DHCP6_OPTION_F_DNS_REMOVAL_INFO         = 116, /* RFC 8156 */
        SD_DHCP6_OPTION_F_DNS_HOST_NAME            = 117, /* RFC 8156 */
        SD_DHCP6_OPTION_F_DNS_ZONE_NAME            = 118, /* RFC 8156 */
        SD_DHCP6_OPTION_F_DNS_FLAGS                = 119, /* RFC 8156 */
        SD_DHCP6_OPTION_F_EXPIRATION_TIME          = 120, /* RFC 8156 */
        SD_DHCP6_OPTION_F_MAX_UNACKED_BNDUPD       = 121, /* RFC 8156 */
        SD_DHCP6_OPTION_F_MCLT                     = 122, /* RFC 8156 */
        SD_DHCP6_OPTION_F_PARTNER_LIFETIME         = 123, /* RFC 8156 */
        SD_DHCP6_OPTION_F_PARTNER_LIFETIME_SENT    = 124, /* RFC 8156 */
        SD_DHCP6_OPTION_F_PARTNER_DOWN_TIME        = 125, /* RFC 8156 */
        SD_DHCP6_OPTION_F_PARTNER_RAW_CLT_TIME     = 126, /* RFC 8156 */
        SD_DHCP6_OPTION_F_PROTOCOL_VERSION         = 127, /* RFC 8156 */
        SD_DHCP6_OPTION_F_KEEPALIVE_TIME           = 128, /* RFC 8156 */
        SD_DHCP6_OPTION_F_RECONFIGURE_DATA         = 129, /* RFC 8156 */
        SD_DHCP6_OPTION_F_RELATIONSHIP_NAME        = 130, /* RFC 8156 */
        SD_DHCP6_OPTION_F_SERVER_FLAGS             = 131, /* RFC 8156 */
        SD_DHCP6_OPTION_F_SERVER_STATE             = 132, /* RFC 8156 */
        SD_DHCP6_OPTION_F_START_TIME_OF_STATE      = 133, /* RFC 8156 */
        SD_DHCP6_OPTION_F_STATE_EXPIRATION_TIME    = 134, /* RFC 8156 */
        SD_DHCP6_OPTION_RELAY_PORT                 = 135, /* RFC 8357 */
        SD_DHCP6_OPTION_V6_SZTP_REDIRECT           = 136, /* RFC 8572 */
        SD_DHCP6_OPTION_S46_BIND_IPV6_PREFIX       = 137, /* RFC 8539 */
        SD_DHCP6_OPTION_IA_LL                      = 138, /* RFC 8947 */
        SD_DHCP6_OPTION_LLADDR                     = 139, /* RFC 8947 */
        SD_DHCP6_OPTION_SLAP_QUAD                  = 140, /* RFC 8948 */
        SD_DHCP6_OPTION_V6_DOTS_RI                 = 141, /* RFC 8973 */
        SD_DHCP6_OPTION_V6_DOTS_ADDRESS            = 142, /* RFC 8973 */
        SD_DHCP6_OPTION_IPV6_ADDRESS_ANDSF         = 143,  /* RFC 6153 */
        SD_DHCP6_OPTION_V6_DNR                     = 144  /* RFC 9463 */
        /* option codes 145-65535 are unassigned */
};

_SD_END_DECLARATIONS;

#endif
