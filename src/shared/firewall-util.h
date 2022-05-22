/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "in-addr-util.h"

typedef struct FirewallContext FirewallContext;

int fw_ctx_new(FirewallContext **ret);
FirewallContext *fw_ctx_free(FirewallContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(FirewallContext *, fw_ctx_free);

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

struct NFTSetContext {
        int nfproto;
        char *table;
        char *set;
};
typedef struct NFTSetContext NFTSetContext;

int nft_set_context_add(NFTSetContext **s, size_t *n, int nfproto, const char *table, const char *set);
NFTSetContext* nft_set_context_free_many(NFTSetContext *s, size_t *n);
int config_parse_nft_set_context(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                NFTSetContext **nft_set_context,
                size_t *n);

const char *nfproto_to_string(int i) _const_;
int nfproto_from_string(const char *s) _pure_;

int nft_set_element_add_in_addr(
                const NFTSetContext *nft_set_context,
                int af,
                const union in_addr_union *address,
                unsigned int prefixlen);
int nft_set_element_del_in_addr(
                const NFTSetContext *nft_set_context,
                int af,
                const union in_addr_union *address,
                unsigned int prefixlen);

int nft_set_element_add_uint32(const NFTSetContext *nft_set_context, uint32_t element);
int nft_set_element_del_uint32(const NFTSetContext *nft_set_context, uint32_t element);
int nft_set_element_add_uint64(const NFTSetContext *nft_set_context, uint64_t element);
int nft_set_element_del_uint64(const NFTSetContext *nft_set_context, uint64_t element);
