/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "in-addr-util.h"
#include "json.h"
#include "network-cloud-util.h"

#define AZURE_METADATA_HEADER            "Metadata:true"
#define AZURE_IMDS_REST_ENDPOINT         "169.254.169.254"
#define AZURE_API_VERSION                "?api-version=2017-04-02"
#define AZURE_NETWORK_METADATA_URL_BASE  "/metadata/instance/network"

typedef struct AzureCloudMetadata {
        union in_addr_union private_ip;
        union in_addr_union public_ip;
        union in_addr_union subnet;

        unsigned char prefixlen;
} AzureCloudMetadata;

int azure_parse_json_object(NetworkCloudManager *m, JsonVariant *j);
int azure_acquire_cloud_metadata_from_imds(bool perform, NetworkCloudManager **ret);
