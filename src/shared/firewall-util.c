/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "alloc-util.h"
#include "firewall-util.h"
#include "firewall-util-private.h"

enum FirewallBackend {
        FW_BACKEND_NONE,
#if HAVE_LIBIPTC
        FW_BACKEND_IPTABLES,
#endif
};

static enum FirewallBackend FirewallBackend;

static enum FirewallBackend firewall_backend_probe(void) {
#if HAVE_LIBIPTC
        return FW_BACKEND_IPTABLES;
#else
        return FW_BACKEND_NONE;
#endif
}

int fw_add_masquerade(
                bool add,
                int af,
                const union in_addr_union *source,
                unsigned source_prefixlen) {

        if (FirewallBackend == FW_BACKEND_NONE)
                FirewallBackend = firewall_backend_probe();

        switch (FirewallBackend) {
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
                bool add,
                int af,
                int protocol,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote) {

        if (FirewallBackend == FW_BACKEND_NONE)
                FirewallBackend = firewall_backend_probe();

        switch (FirewallBackend) {
        case FW_BACKEND_NONE:
                return -EOPNOTSUPP;
#if HAVE_LIBIPTC
        case FW_BACKEND_IPTABLES:
                return fw_iptables_add_local_dnat(add, af, protocol, local_port, remote, remote_port, previous_remote);
#endif
        }

        return -EOPNOTSUPP;
}
