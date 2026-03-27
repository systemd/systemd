/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcp6relayhfoo
#define foosddhcp6relayhfoo

#include <netinet/in.h>

#include "_sd-common.h"
#include "sd-event.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp6_relay sd_dhcp6_relay;

int sd_dhcp6_relay_new(sd_dhcp6_relay **ret);

_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_relay);

int sd_dhcp6_relay_set_ifindex(sd_dhcp6_relay *relay, int ifindex);
int sd_dhcp6_relay_set_ifname(sd_dhcp6_relay *relay, const char *ifname);
int sd_dhcp6_relay_get_ifname(sd_dhcp6_relay *relay, const char **ret);
int sd_dhcp6_relay_set_event(sd_dhcp6_relay *relay, sd_event *event, int64_t priority);
int sd_dhcp6_relay_set_link_local_address(sd_dhcp6_relay *relay, const struct in6_addr *address);
int sd_dhcp6_relay_set_relay_target(sd_dhcp6_relay *relay, const struct in6_addr *target);
int sd_dhcp6_relay_set_interface_id(sd_dhcp6_relay *relay, const char *interface_id);

int sd_dhcp6_relay_start(sd_dhcp6_relay *relay);
int sd_dhcp6_relay_stop(sd_dhcp6_relay *relay);
int sd_dhcp6_relay_is_running(sd_dhcp6_relay *relay);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp6_relay, sd_dhcp6_relay_unref);

_SD_END_DECLARATIONS;

#endif
