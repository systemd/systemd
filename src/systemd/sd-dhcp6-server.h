/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcp6serverhfoo
#define foosddhcp6serverhfoo

#include <netinet/in.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_event sd_event;
typedef struct sd_dhcp6_server sd_dhcp6_server;

int sd_dhcp6_server_new(sd_dhcp6_server **ret, int ifindex);

int sd_dhcp6_server_set_ifname(sd_dhcp6_server *server, const char *ifname);
int sd_dhcp6_server_get_ifname(sd_dhcp6_server *server, const char **ret);

_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_server);

int sd_dhcp6_server_attach_event(sd_dhcp6_server *server, sd_event *event, int64_t priority);
int sd_dhcp6_server_detach_event(sd_dhcp6_server *server);
sd_event *sd_dhcp6_server_get_event(sd_dhcp6_server *server);

int sd_dhcp6_server_is_running(sd_dhcp6_server *server);

int sd_dhcp6_server_start(sd_dhcp6_server *server);
int sd_dhcp6_server_stop(sd_dhcp6_server *server);

int sd_dhcp6_server_set_address(sd_dhcp6_server *server, const struct in6_addr *address, unsigned char prefixlen);
int sd_dhcp6_server_configure_pool(sd_dhcp6_server *server, const struct in6_addr *address, unsigned char prefixlen, uint64_t pool_offset, uint64_t pool_size);

int sd_dhcp6_server_set_timezone(sd_dhcp6_server *server, const char *tz);
int sd_dhcp6_server_set_dns(sd_dhcp6_server *server, const struct in6_addr dns[], size_t n);
int sd_dhcp6_server_set_ntp(sd_dhcp6_server *server, const struct in6_addr ntp[], size_t n);

int sd_dhcp6_server_set_max_lease_time(sd_dhcp6_server *server, uint64_t t);
int sd_dhcp6_server_set_default_lease_time(sd_dhcp6_server *server, uint64_t t);
int sd_dhcp6_server_set_rapid_commit(sd_dhcp6_server *server, int enabled);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp6_server, sd_dhcp6_server_unref);

_SD_END_DECLARATIONS;

#endif
