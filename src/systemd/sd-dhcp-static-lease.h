/* SPDX-License-Identifier: LGPL-2.1+ */

#include <inttypes.h>
#include <sys/types.h>

#include "sparse-endian.h"

#include "_sd-common.h"


extern const struct hash_ops dhcp_static_leases_hash_ops;

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp_static_lease sd_dhcp_static_lease;
typedef struct DHCPClientId DHCPClientId;

int sd_dhcp_static_lease_new(DHCPClientId *client_id, be32_t address, sd_dhcp_static_lease **ret);
sd_dhcp_static_lease *sd_dhcp_static_lease_ref(sd_dhcp_static_lease *ra);
sd_dhcp_static_lease *sd_dhcp_static_lease_unref(sd_dhcp_static_lease *ra);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_static_lease, sd_dhcp_static_lease_unref);

_SD_END_DECLARATIONS;
