/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
***/

#include <sys/ioctl.h>
#include <net/if.h>

#include "sd-resolve.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "wireguard.h"
#include "wireguard-netlink.h"

static void resolve_endpoints(NetDev *netdev);

static WireguardPeer *wireguard_peer_new(Wireguard *w, unsigned section) {
        WireguardPeer *peer;

        assert(w);

        if (w->last_peer_section == section && w->peers)
                return w->peers;

        peer = new(WireguardPeer, 1);
        if (!peer)
                return NULL;

        *peer = (WireguardPeer) {
                .flags = WGPEER_F_REPLACE_ALLOWEDIPS,
        };

        LIST_PREPEND(peers, w->peers, peer);
        w->last_peer_section = section;

        return peer;
}

static int set_wireguard_interface(NetDev *netdev) {
        int r;
        unsigned i, j;
        WireguardPeer *peer, *peer_start;
        WireguardIPmask *mask, *mask_start = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        Wireguard *w;
        uint32_t serial;

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        peer_start = w->peers;

        do {
                message = sd_netlink_message_unref(message);

                r = sd_genl_message_new(netdev->manager->genl, SD_GENL_WIREGUARD, WG_CMD_SET_DEVICE, &message);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Failed to allocate generic netlink message: %m");

                r = sd_netlink_message_append_string(message, WGDEVICE_A_IFNAME, netdev->ifname);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append wireguard interface name: %m");

                if (peer_start == w->peers) {
                        r = sd_netlink_message_append_data(message, WGDEVICE_A_PRIVATE_KEY, &w->private_key, WG_KEY_LEN);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append wireguard private key: %m");

                        r = sd_netlink_message_append_u16(message, WGDEVICE_A_LISTEN_PORT, w->port);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append wireguard port: %m");

                        r = sd_netlink_message_append_u32(message, WGDEVICE_A_FWMARK, w->fwmark);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append wireguard fwmark: %m");

                        r = sd_netlink_message_append_u32(message, WGDEVICE_A_FLAGS, w->flags);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append wireguard flags: %m");
                }

                r = sd_netlink_message_open_container(message, WGDEVICE_A_PEERS);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append wireguard peer attributes: %m");

                i = 0;

                LIST_FOREACH(peers, peer, peer_start) {
                        r = sd_netlink_message_open_array(message, ++i);
                        if (r < 0)
                                break;

                        r = sd_netlink_message_append_data(message, WGPEER_A_PUBLIC_KEY, &peer->public_key, sizeof(peer->public_key));
                        if (r < 0)
                                break;

                        if (!mask_start) {
                                r = sd_netlink_message_append_data(message, WGPEER_A_PRESHARED_KEY, &peer->preshared_key, WG_KEY_LEN);
                                if (r < 0)
                                        break;

                                r = sd_netlink_message_append_u32(message, WGPEER_A_FLAGS, peer->flags);
                                if (r < 0)
                                        break;

                                r = sd_netlink_message_append_u16(message, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, peer->persistent_keepalive_interval);
                                if (r < 0)
                                        break;

                                if (peer->endpoint.sa.sa_family == AF_INET) {
                                        r = sd_netlink_message_append_data(message, WGPEER_A_ENDPOINT, &peer->endpoint.in, sizeof(peer->endpoint.in));
                                        if (r < 0)
                                                break;
                                } else if (peer->endpoint.sa.sa_family == AF_INET6) {
                                        r = sd_netlink_message_append_data(message, WGPEER_A_ENDPOINT, &peer->endpoint.in6, sizeof(peer->endpoint.in6));
                                        if (r < 0)
                                                break;
                                }

                                mask_start = peer->ipmasks;
                        }

                        r = sd_netlink_message_open_container(message, WGPEER_A_ALLOWEDIPS);
                        if (r < 0) {
                                mask_start = NULL;
                                break;
                        }
                        j = 0;
                        LIST_FOREACH(ipmasks, mask, mask_start) {
                                r = sd_netlink_message_open_array(message, ++j);
                                if (r < 0)
                                        break;

                                r = sd_netlink_message_append_u16(message, WGALLOWEDIP_A_FAMILY, mask->family);
                                if (r < 0)
                                        break;

                                if (mask->family == AF_INET) {
                                        r = sd_netlink_message_append_in_addr(message, WGALLOWEDIP_A_IPADDR, &mask->ip.in);
                                        if (r < 0)
                                                break;
                                } else if (mask->family == AF_INET6) {
                                        r = sd_netlink_message_append_in6_addr(message, WGALLOWEDIP_A_IPADDR, &mask->ip.in6);
                                        if (r < 0)
                                                break;
                                }

                                r = sd_netlink_message_append_u8(message, WGALLOWEDIP_A_CIDR_MASK, mask->cidr);
                                if (r < 0)
                                        break;

                                r = sd_netlink_message_close_container(message);
                                if (r < 0)
                                        return log_netdev_error_errno(netdev, r, "Could not add wireguard allowed ip: %m");
                        }
                        mask_start = mask;
                        if (mask_start) {
                                r = sd_netlink_message_cancel_array(message);
                                if (r < 0)
                                        return log_netdev_error_errno(netdev, r, "Could not cancel wireguard allowed ip message attribute: %m");
                        }
                        r = sd_netlink_message_close_container(message);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not add wireguard allowed ip: %m");

                        r = sd_netlink_message_close_container(message);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not add wireguard peer: %m");
                }

                peer_start = peer;
                if (peer_start && !mask_start) {
                        r = sd_netlink_message_cancel_array(message);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not cancel wireguard peers: %m");
                }

                r = sd_netlink_message_close_container(message);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not close wireguard container: %m");

                r = sd_netlink_send(netdev->manager->genl, message, &serial);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not set wireguard device: %m");

        } while (peer || mask_start);

        return 0;
}

static WireguardEndpoint* wireguard_endpoint_free(WireguardEndpoint *e) {
        if (!e)
                return NULL;
        e->host = mfree(e->host);
        e->port = mfree(e->port);
        return mfree(e);
}

static void wireguard_endpoint_destroy_callback(void *userdata) {
        WireguardEndpoint *e = userdata;

        assert(e);
        assert(e->netdev);

        netdev_unref(e->netdev);
        wireguard_endpoint_free(e);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(WireguardEndpoint*, wireguard_endpoint_free);

static int on_resolve_retry(sd_event_source *s, usec_t usec, void *userdata) {
        NetDev *netdev = userdata;
        Wireguard *w;

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        if (!netdev->manager)
                /* The netdev is detached. */
                return 0;

        assert(!w->unresolved_endpoints);
        w->unresolved_endpoints = TAKE_PTR(w->failed_endpoints);

        resolve_endpoints(netdev);

        return 0;
}

/*
 * Given the number of retries this function will return will an exponential
 * increasing time in milliseconds to wait starting at 200ms and capped at 25 seconds.
 */
static int exponential_backoff_milliseconds(unsigned n_retries) {
        return (2 << MAX(n_retries, 7U)) * 100 * USEC_PER_MSEC;
}

static int wireguard_resolve_handler(sd_resolve_query *q,
                                     int ret,
                                     const struct addrinfo *ai,
                                     void *userdata) {
        _cleanup_(netdev_unrefp) NetDev *netdev_will_unrefed = NULL;
        NetDev *netdev = NULL;
        WireguardEndpoint *e;
        Wireguard *w;
        int r;

        assert(userdata);
        e = userdata;
        netdev = e->netdev;

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        if (!netdev->manager)
                /* The netdev is detached. */
                return 0;

        if (ret != 0) {
                log_netdev_error(netdev, "Failed to resolve host '%s:%s': %s", e->host, e->port, gai_strerror(ret));
                LIST_PREPEND(endpoints, w->failed_endpoints, e);
                (void) sd_resolve_query_set_destroy_callback(q, NULL); /* Avoid freeing endpoint by destroy callback. */
                netdev_will_unrefed = netdev; /* But netdev needs to be unrefed. */
        } else if ((ai->ai_family == AF_INET && ai->ai_addrlen == sizeof(struct sockaddr_in)) ||
                   (ai->ai_family == AF_INET6 && ai->ai_addrlen == sizeof(struct sockaddr_in6)))
                memcpy(&e->peer->endpoint, ai->ai_addr, ai->ai_addrlen);
        else
                log_netdev_error(netdev, "Neither IPv4 nor IPv6 address found for peer endpoint: %s:%s", e->host, e->port);

        if (w->unresolved_endpoints) {
                resolve_endpoints(netdev);
                return 0;
        }

        set_wireguard_interface(netdev);
        if (w->failed_endpoints) {
                _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;

                w->n_retries++;
                r = sd_event_add_time(netdev->manager->event,
                                      &s,
                                      CLOCK_MONOTONIC,
                                      now(CLOCK_MONOTONIC) + exponential_backoff_milliseconds(w->n_retries),
                                      0,
                                      on_resolve_retry,
                                      netdev);
                if (r < 0) {
                        log_netdev_warning_errno(netdev, r, "Could not arm resolve retry handler: %m");
                        return 0;
                }

                r = sd_event_source_set_destroy_callback(s, (sd_event_destroy_t) netdev_destroy_callback);
                if (r < 0) {
                        log_netdev_warning_errno(netdev, r, "Failed to set destroy callback to event source: %m");
                        return 0;
                }

                (void) sd_event_source_set_floating(s, true);
                netdev_ref(netdev);
        }

        return 0;
}

static void resolve_endpoints(NetDev *netdev) {
        static const struct addrinfo hints = {
                .ai_family = AF_UNSPEC,
                .ai_socktype = SOCK_DGRAM,
                .ai_protocol = IPPROTO_UDP
        };
        WireguardEndpoint *endpoint;
        Wireguard *w;
        int r = 0;

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        LIST_FOREACH(endpoints, endpoint, w->unresolved_endpoints) {
                _cleanup_(sd_resolve_query_unrefp) sd_resolve_query *q = NULL;

                r = sd_resolve_getaddrinfo(netdev->manager->resolve,
                                           &q,
                                           endpoint->host,
                                           endpoint->port,
                                           &hints,
                                           wireguard_resolve_handler,
                                           endpoint);

                if (r == -ENOBUFS)
                        break;
                if (r < 0) {
                        log_netdev_error_errno(netdev, r, "Failed to create resolver: %m");
                        continue;
                }

                r = sd_resolve_query_set_destroy_callback(q, wireguard_endpoint_destroy_callback);
                if (r < 0) {
                        log_netdev_error_errno(netdev, r, "Failed to set destroy callback to resolving query: %m");
                        continue;
                }

                (void) sd_resolve_query_set_floating(q, true);

                /* Avoid freeing netdev. It will be unrefed by the destroy callback. */
                netdev_ref(netdev);

                LIST_REMOVE(endpoints, w->unresolved_endpoints, endpoint);
        }
}

static int netdev_wireguard_post_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Wireguard *w;

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        set_wireguard_interface(netdev);
        resolve_endpoints(netdev);
        return 0;
}

int config_parse_wireguard_listen_port(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {
        uint16_t *s = data;
        uint16_t port = 0;
        int r;

        assert(rvalue);
        assert(data);

        if (!streq(rvalue, "auto")) {
                r = parse_ip_port(rvalue, &port);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid port specification, ignoring assignment: %s", rvalue);
        }

        *s = port;

        return 0;
}

static int parse_wireguard_key(const char *unit,
                               const char *filename,
                               unsigned line,
                               const char *section,
                               unsigned section_line,
                               const char *lvalue,
                               int ltype,
                               const char *rvalue,
                               void *data,
                               void *userdata) {
        _cleanup_free_ void *key = NULL;
        size_t len;
        int r;

        assert(filename);
        assert(rvalue);
        assert(userdata);

        r = unbase64mem(rvalue, strlen(rvalue), &key, &len);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Could not parse wireguard key \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }
        if (len != WG_KEY_LEN) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Wireguard key is too short, ignoring assignment: %s", rvalue);
                return 0;
        }

        memcpy(userdata, key, WG_KEY_LEN);
        return true;
}

int config_parse_wireguard_private_key(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {
        Wireguard *w;

        assert(data);

        w = WIREGUARD(data);

        assert(w);

        return parse_wireguard_key(unit,
                                   filename,
                                   line,
                                   section,
                                   section_line,
                                   lvalue,
                                   ltype,
                                   rvalue,
                                   data,
                                   &w->private_key);

}

int config_parse_wireguard_preshared_key(const char *unit,
                                         const char *filename,
                                         unsigned line,
                                         const char *section,
                                         unsigned section_line,
                                         const char *lvalue,
                                         int ltype,
                                         const char *rvalue,
                                         void *data,
                                         void *userdata) {
        Wireguard *w;
        WireguardPeer *peer;

        assert(data);

        w = WIREGUARD(data);

        assert(w);

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        return parse_wireguard_key(unit,
                                   filename,
                                   line,
                                   section,
                                   section_line,
                                   lvalue,
                                   ltype,
                                   rvalue,
                                   data,
                                   peer->preshared_key);
}

int config_parse_wireguard_public_key(const char *unit,
                                      const char *filename,
                                      unsigned line,
                                      const char *section,
                                      unsigned section_line,
                                      const char *lvalue,
                                      int ltype,
                                      const char *rvalue,
                                      void *data,
                                      void *userdata) {
        Wireguard *w;
        WireguardPeer *peer;

        assert(data);

        w = WIREGUARD(data);

        assert(w);

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        return parse_wireguard_key(unit,
                                   filename,
                                   line,
                                   section,
                                   section_line,
                                   lvalue,
                                   ltype,
                                   rvalue,
                                   data,
                                   peer->public_key);
}

int config_parse_wireguard_allowed_ips(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {
        union in_addr_union addr;
        unsigned char prefixlen;
        int r, family;
        Wireguard *w;
        WireguardPeer *peer;
        WireguardIPmask *ipmask;

        assert(rvalue);
        assert(data);

        w = WIREGUARD(data);

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&rvalue, &word, "," WHITESPACE, 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to split allowed ips \"%s\" option: %m", rvalue);
                        break;
                }

                r = in_addr_prefix_from_string_auto(word, &family, &addr, &prefixlen);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Network address is invalid, ignoring assignment: %s", word);
                        return 0;
                }

                ipmask = new(WireguardIPmask, 1);
                if (!ipmask)
                        return log_oom();

                *ipmask = (WireguardIPmask) {
                        .family = family,
                        .ip.in6 = addr.in6,
                        .cidr = prefixlen,
                };

                LIST_PREPEND(ipmasks, peer->ipmasks, ipmask);
        }

        return 0;
}

int config_parse_wireguard_endpoint(const char *unit,
                                    const char *filename,
                                    unsigned line,
                                    const char *section,
                                    unsigned section_line,
                                    const char *lvalue,
                                    int ltype,
                                    const char *rvalue,
                                    void *data,
                                    void *userdata) {
        Wireguard *w;
        WireguardPeer *peer;
        size_t len;
        const char *begin, *end = NULL;
        _cleanup_free_ char *host = NULL, *port = NULL;
        _cleanup_(wireguard_endpoint_freep) WireguardEndpoint *endpoint = NULL;

        assert(data);
        assert(rvalue);

        w = WIREGUARD(data);

        assert(w);

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        if (rvalue[0] == '[') {
                begin = &rvalue[1];
                end = strchr(rvalue, ']');
                if (!end) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Unable to find matching brace of endpoint, ignoring assignment: %s", rvalue);
                        return 0;
                }
                len = end - begin;
                ++end;
                if (*end != ':' || !*(end + 1)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Unable to find port of endpoint: %s", rvalue);
                        return 0;
                }
                ++end;
        } else {
                begin = rvalue;
                end = strrchr(rvalue, ':');
                if (!end || !*(end + 1)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Unable to find port of endpoint: %s", rvalue);
                        return 0;
                }
                len = end - begin;
                ++end;
        }

        host = strndup(begin, len);
        if (!host)
                return log_oom();

        port = strdup(end);
        if (!port)
                return log_oom();

        endpoint = new(WireguardEndpoint, 1);
        if (!endpoint)
                return log_oom();

        *endpoint = (WireguardEndpoint) {
                .peer = TAKE_PTR(peer),
                .host = TAKE_PTR(host),
                .port = TAKE_PTR(port),
                .netdev = data,
        };
        LIST_PREPEND(endpoints, w->unresolved_endpoints, TAKE_PTR(endpoint));

        return 0;
}

int config_parse_wireguard_keepalive(const char *unit,
                                     const char *filename,
                                     unsigned line,
                                     const char *section,
                                     unsigned section_line,
                                     const char *lvalue,
                                     int ltype,
                                     const char *rvalue,
                                     void *data,
                                     void *userdata) {
        int r;
        uint16_t keepalive = 0;
        Wireguard *w;
        WireguardPeer *peer;

        assert(rvalue);
        assert(data);

        w = WIREGUARD(data);

        assert(w);

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        if (streq(rvalue, "off"))
                keepalive = 0;
        else {
                r = safe_atou16(rvalue, &keepalive);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "The persistent keepalive interval must be 0-65535. Ignore assignment: %s", rvalue);
        }

        peer->persistent_keepalive_interval = keepalive;
        return 0;
}

static void wireguard_init(NetDev *netdev) {
        Wireguard *w;

        assert(netdev);

        w = WIREGUARD(netdev);

        assert(w);

        w->flags = WGDEVICE_F_REPLACE_PEERS;
}

static void wireguard_done(NetDev *netdev) {
        Wireguard *w;
        WireguardPeer *peer;
        WireguardIPmask *mask;
        WireguardEndpoint *e;

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        while ((peer = w->peers)) {
                LIST_REMOVE(peers, w->peers, peer);
                while ((mask = peer->ipmasks)) {
                        LIST_REMOVE(ipmasks, peer->ipmasks, mask);
                        free(mask);
                }
                free(peer);
        }

        while ((e = w->unresolved_endpoints)) {
                LIST_REMOVE(endpoints, w->unresolved_endpoints, e);
                wireguard_endpoint_free(e);
        }

        while ((e = w->failed_endpoints)) {
                LIST_REMOVE(endpoints, w->failed_endpoints, e);
                wireguard_endpoint_free(e);
        }
}

const NetDevVTable wireguard_vtable = {
        .object_size = sizeof(Wireguard),
        .sections = "Match\0NetDev\0WireGuard\0WireGuardPeer\0",
        .post_create = netdev_wireguard_post_create,
        .init = wireguard_init,
        .done = wireguard_done,
        .create_type = NETDEV_CREATE_INDEPENDENT,
};
