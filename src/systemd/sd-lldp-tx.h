/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdlldptxhfoo
#define foosdlldptxhfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <sys/types.h>

#include "sd-event.h"
#include "sd-lldp.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_lldp_tx sd_lldp_tx;

__extension__ typedef enum sd_lldp_multicast_mode_t {
        SD_LLDP_MULTICAST_MODE_NEAREST_BRIDGE,
        SD_LLDP_MULTICAST_MODE_NON_TPMR_BRIDGE,
        SD_LLDP_MULTICAST_MODE_CUSTOMER_BRIDGE,
        _SD_LLDP_MULTICAST_MODE_MAX,
        _SD_LLDP_MULTICAST_MODE_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(LLDP_TX_MODE)
} sd_lldp_multicast_mode_t;

int sd_lldp_tx_new(sd_lldp_tx **ret);
sd_lldp_tx *sd_lldp_tx_ref(sd_lldp_tx *lldp_tx);
sd_lldp_tx *sd_lldp_tx_unref(sd_lldp_tx *lldp_tx);

int sd_lldp_tx_start(sd_lldp_tx *lldp_tx);
int sd_lldp_tx_stop(sd_lldp_tx *lldp_tx);
int sd_lldp_tx_is_running(sd_lldp_tx *lldp_tx);

int sd_lldp_tx_attach_event(sd_lldp_tx *lldp_tx, sd_event *event, int64_t priority);
int sd_lldp_tx_detach_event(sd_lldp_tx *lldp_tx);

int sd_lldp_tx_set_ifindex(sd_lldp_tx *lldp_tx, int ifindex);
int sd_lldp_tx_set_ifname(sd_lldp_tx *lldp_tx, const char *ifname);
int sd_lldp_tx_get_ifname(sd_lldp_tx *lldp_tx, const char **ret);

int sd_lldp_tx_set_multicast_mode(sd_lldp_tx *lldp_tx, sd_lldp_multicast_mode_t mode);
int sd_lldp_tx_set_hwaddr(sd_lldp_tx *lldp_tx, const struct ether_addr *hwaddr);
int sd_lldp_tx_set_port_description(sd_lldp_tx *lldp_tx, const char *port_description);
int sd_lldp_tx_set_hostname(sd_lldp_tx *lldp_tx, const char *hostname);
int sd_lldp_tx_set_pretty_hostname(sd_lldp_tx *lldp_tx, const char *pretty_hostname);
int sd_lldp_tx_set_mud_url(sd_lldp_tx *lldp_tx, const char *mud_url);
int sd_lldp_tx_set_capabilities(sd_lldp_tx *lldp_tx, uint16_t supported, uint16_t enabled);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_lldp_tx, sd_lldp_tx_unref);

_SD_END_DECLARATIONS;

#endif
