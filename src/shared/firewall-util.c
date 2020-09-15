/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "alloc-util.h"
#include "firewall-util.h"
#include "firewall-util-private.h"

static enum FirewallBackend firewall_backend_probe(void) {
#if HAVE_LIBIPTC
        return FW_BACKEND_IPTABLES;
#else
        return FW_BACKEND_NONE;
#endif
}

int fw_ctx_new(FirewallContext **ret) {
        _cleanup_free_ FirewallContext *ctx = NULL;

        ctx = new0(FirewallContext, 1);
        if (!ctx)
                return -ENOMEM;

         *ret = TAKE_PTR(ctx);
         return 0;
}

FirewallContext *fw_ctx_free(FirewallContext *ctx) {
        return mfree(ctx);
}

int fw_add_masquerade(
                FirewallContext **fw_ctx,
                bool add,
                int af,
                const union in_addr_union *source,
                unsigned source_prefixlen) {
        FirewallContext *ctx;
        int r;

        if (!*fw_ctx) {
                r = fw_ctx_new(fw_ctx);
                if (r < 0)
                        return r;
        }

        ctx = *fw_ctx;
        if (ctx->firewall_backend == FW_BACKEND_NONE)
                ctx->firewall_backend = firewall_backend_probe();

        switch (ctx->firewall_backend) {
        case FW_BACKEND_NONE:
                return -EOPNOTSUPP;
#if HAVE_LIBIPTC
        case FW_BACKEND_IPTABLES:
                return fw_iptables_add_masquerade(add, af, source, source_prefixlen);
#endif
        }

        return -EOPNOTSUPP;
}

int fw_add_local_dnat(
                FirewallContext **fw_ctx,
                bool add,
                int af,
                int protocol,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote) {
        FirewallContext *ctx;

        if (!*fw_ctx) {
                int ret = fw_ctx_new(fw_ctx);
                if (ret < 0)
                        return ret;
        }

        ctx = *fw_ctx;
        if (ctx->firewall_backend == FW_BACKEND_NONE)
                ctx->firewall_backend = firewall_backend_probe();

        switch (ctx->firewall_backend) {
        case FW_BACKEND_NONE:
                return -EOPNOTSUPP;
#if HAVE_LIBIPTC
        case FW_BACKEND_IPTABLES:
                return fw_iptables_add_local_dnat(add, af, protocol, local_port, remote, remote_port, previous_remote);
#endif
        }

        return -EOPNOTSUPP;
}
