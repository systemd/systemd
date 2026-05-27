/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"
#include "sparse-endian.h"

struct in_pktinfo;
struct iphdr;
struct udphdr;

typedef struct sd_dhcp_client sd_dhcp_client;
typedef struct sd_dhcp_client_id sd_dhcp_client_id;
typedef struct sd_dhcp_duid sd_dhcp_duid;
typedef struct sd_dhcp_lease sd_dhcp_lease;
typedef struct sd_dhcp_message sd_dhcp_message;
typedef struct sd_dhcp_relay sd_dhcp_relay;
typedef struct sd_dhcp_relay_interface sd_dhcp_relay_interface;
typedef struct sd_dhcp_route sd_dhcp_route;
typedef struct sd_dhcp_server sd_dhcp_server;
typedef struct sd_dhcp_server_lease sd_dhcp_server_lease;

typedef struct DHCPMessageHeader DHCPMessageHeader;
typedef struct DHCPRequest DHCPRequest;
typedef struct DHCPServerData DHCPServerData;

typedef struct TLV TLV;
