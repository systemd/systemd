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

const char *nfproto_to_string(int i) _const_;
int nfproto_from_string(const char *s) _pure_;

int nft_set_element_add_uint32(const NFTSetContext *nft_set_context, uint32_t element);
int nft_set_element_del_uint32(const NFTSetContext *nft_set_context, uint32_t element);
