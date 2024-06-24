/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "conf-parser.h"
#include "in-addr-util.h"

typedef struct FirewallContext FirewallContext;

int fw_ctx_new(FirewallContext **ret);
int fw_ctx_new_full(FirewallContext **ret, bool init_tables);
FirewallContext *fw_ctx_free(FirewallContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(FirewallContext *, fw_ctx_free);

size_t fw_ctx_get_reply_callback_count(FirewallContext *ctx);

int fw_add_masquerade(
                FirewallContext **ctx,
                bool add,
                int af,
                const union in_addr_union *source,
                unsigned source_prefixlen);

int fw_add_local_dnat(
                FirewallContext **ctx,
                bool add,
                int af,
                int protocol,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote);

typedef enum NFTSetSource {
        NFT_SET_SOURCE_ADDRESS,
        NFT_SET_SOURCE_PREFIX,
        NFT_SET_SOURCE_IFINDEX,
        NFT_SET_SOURCE_CGROUP,
        NFT_SET_SOURCE_USER,
        NFT_SET_SOURCE_GROUP,
        _NFT_SET_SOURCE_MAX,
        _NFT_SET_SOURCE_INVALID = -EINVAL,
} NFTSetSource;

typedef struct NFTSet {
        NFTSetSource source;
        int nfproto;
        char *table;
        char *set;
} NFTSet;

typedef struct NFTSetContext {
        NFTSet *sets;
        size_t n_sets;
} NFTSetContext;

void nft_set_context_clear(NFTSetContext *s);
int nft_set_context_dup(const NFTSetContext *src, NFTSetContext *dst);

const char* nfproto_to_string(int i) _const_;
int nfproto_from_string(const char *s) _pure_;

const char* nft_set_source_to_string(int i) _const_;
int nft_set_source_from_string(const char *s) _pure_;

int nft_set_element_modify_iprange(
                FirewallContext *ctx,
                bool add,
                int nfproto,
                int af,
                const char *table,
                const char *set,
                const union in_addr_union *source,
                unsigned int source_prefixlen);

int nft_set_element_modify_ip(
                FirewallContext *ctx,
                bool add,
                int nfproto,
                int af,
                const char *table,
                const char *set,
                const union in_addr_union *source);

int nft_set_element_modify_any(
                FirewallContext *ctx,
                bool add,
                int nfproto,
                const char *table,
                const char *set,
                const void *element,
                size_t element_size);

int nft_set_add(NFTSetContext *s, NFTSetSource source, int nfproto, const char *table, const char *set);

typedef enum NFTSetParseFlags {
        NFT_SET_PARSE_NETWORK,
        NFT_SET_PARSE_CGROUP,
} NFTSetParseFlags;

CONFIG_PARSER_PROTOTYPE(config_parse_nft_set);
