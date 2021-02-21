/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <curl/curl.h>

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "hashmap.h"

typedef enum CloudProvider {
        CLOUD_PROVIDER_AZURE,
        CLOUD_PROVIDER_GCP,
        CLOUD_PROVIDER_EC2,
} CloudProvider;

typedef struct NetworkCloudMetaData {
        struct ether_addr mac;

        OrderedHashmap *ipv4;
} NetworkCloudMetaData;

typedef struct NetworkCloudProvider {
        CloudProvider provider;

        char *payload;
        size_t payload_size;
        size_t payload_allocated;

        OrderedHashmap *interfaces_by_mac;
} NetworkCloudProvider;

int network_cloud_provider_new(CloudProvider provider, NetworkCloudProvider **ret);
void *network_cloud_provider_free(NetworkCloudProvider *m);
size_t network_cloud_meta_data_write_callback(void *contents, size_t size, size_t nmemb, void *userdata);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(NetworkCloudProvider*, network_cloud_provider_free, NULL);

int network_cloud_metadata_new(NetworkCloudMetaData **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(CURL*, curl_easy_cleanup, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct curl_slist*, curl_slist_free_all, NULL);
