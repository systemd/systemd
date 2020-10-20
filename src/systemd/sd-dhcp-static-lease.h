/* SPDX-License-Identifier: LGPL-2.1+ */
#ifndef foosddhcpstaticleasehfoo
#define foosddhcpstaticleasehfoo

#include "_sd-common.h"
#include <netinet/in.h>

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp_static_lease sd_dhcp_static_lease;

int sd_dhcp_static_lease_new(sd_dhcp_static_lease **ret);
int sd_dhcp_static_lease_set_client_id_by_mac(sd_dhcp_static_lease *lease, const uint8_t *mac_addr, size_t mac_addr_size);
int sd_dhcp_static_lease_unset_client_id(sd_dhcp_static_lease *lease);
int sd_dhcp_static_lease_is_address_set(sd_dhcp_static_lease *lease);
int sd_dhcp_static_lease_set_address(sd_dhcp_static_lease *lease, const struct in_addr *address);
int sd_dhcp_static_lease_unset_address(sd_dhcp_static_lease *lease);

sd_dhcp_static_lease *sd_dhcp_static_lease_ref(sd_dhcp_static_lease *ra);
sd_dhcp_static_lease *sd_dhcp_static_lease_unref(sd_dhcp_static_lease *ra);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_static_lease, sd_dhcp_static_lease_unref);

_SD_END_DECLARATIONS;

#endif
