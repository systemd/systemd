#pragma once

typedef struct Wireguard Wireguard;

#include "in-addr-util.h"
#include "netdev.h"
#include "socket-util.h"
#include "wireguard-netlink.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

typedef struct WireguardIPmask {
        uint16_t family;
        union in_addr_union ip;
        uint8_t cidr;

        LIST_FIELDS(struct WireguardIPmask, ipmasks);
} WireguardIPmask;

typedef struct WireguardPeer {
        uint8_t public_key[WG_KEY_LEN];
        uint8_t preshared_key[WG_KEY_LEN];
        uint32_t flags;

        union sockaddr_union endpoint;

        uint16_t persistent_keepalive_interval;

        LIST_HEAD(WireguardIPmask, ipmasks);
        LIST_FIELDS(struct WireguardPeer, peers);
} WireguardPeer;

typedef struct WireguardEndpoint {
        char *host;
        char *port;

        NetDev *netdev;
        WireguardPeer *peer;

        LIST_FIELDS(struct WireguardEndpoint, endpoints);
} WireguardEndpoint;

struct Wireguard {
        NetDev meta;
        unsigned last_peer_section;

        char interface[IFNAMSIZ];
        uint32_t flags;

        uint8_t public_key[WG_KEY_LEN];
        uint8_t private_key[WG_KEY_LEN];
        uint32_t fwmark;

        uint16_t port;

        LIST_HEAD(WireguardPeer, peers);
        size_t allocation_size;

        LIST_HEAD(WireguardEndpoint, unresolved_endpoints);
        LIST_HEAD(WireguardEndpoint, failed_endpoints);
        unsigned n_retries;
};

DEFINE_NETDEV_CAST(WIREGUARD, Wireguard);
extern const NetDevVTable wireguard_vtable;

int config_parse_wireguard_allowed_ips(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_wireguard_endpoint(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_wireguard_listen_port(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_wireguard_public_key(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_wireguard_private_key(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_wireguard_preshared_key(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_wireguard_keepalive(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
