/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
***/

#include <linux/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>

#include "sd-netlink.h"
#include "sd-resolve.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "creds-util.h"
#include "dns-domain.h"
#include "event-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "memory-util.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-route.h"
#include "networkd-route-util.h"
#include "networkd-util.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "random-util.h"
#include "set.h"
#include "string-util.h"
#include "wireguard.h"

static void wireguard_resolve_endpoints(NetDev *netdev);
static int peer_resolve_endpoint(WireguardPeer *peer);

static void wireguard_peer_clear_ipmasks(WireguardPeer *peer) {
        assert(peer);

        LIST_CLEAR(ipmasks, peer->ipmasks, free);
}

static WireguardPeer* wireguard_peer_free(WireguardPeer *peer) {
        if (!peer)
                return NULL;

        if (peer->wireguard) {
                LIST_REMOVE(peers, peer->wireguard->peers, peer);

                if (peer->section)
                        hashmap_remove(peer->wireguard->peers_by_section, peer->section);
        }

        config_section_free(peer->section);

        wireguard_peer_clear_ipmasks(peer);

        free(peer->endpoint_host);
        free(peer->endpoint_port);
        free(peer->public_key_file);
        free(peer->preshared_key_file);
        explicit_bzero_safe(peer->preshared_key, WG_KEY_LEN);

        sd_event_source_disable_unref(peer->resolve_retry_event_source);
        sd_resolve_query_unref(peer->resolve_query);

        return mfree(peer);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(WireguardPeer, wireguard_peer_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                wireguard_peer_hash_ops_by_section,
                ConfigSection, config_section_hash_func, config_section_compare_func,
                WireguardPeer, wireguard_peer_free);

static int wireguard_peer_new_static(Wireguard *w, const char *filename, unsigned section_line, WireguardPeer **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(wireguard_peer_freep) WireguardPeer *peer = NULL;
        int r;

        assert(w);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        peer = hashmap_get(w->peers_by_section, n);
        if (peer) {
                *ret = TAKE_PTR(peer);
                return 0;
        }

        peer = new(WireguardPeer, 1);
        if (!peer)
                return -ENOMEM;

        *peer = (WireguardPeer) {
                .flags = WGPEER_F_REPLACE_ALLOWEDIPS,
                .wireguard = w,
                .section = TAKE_PTR(n),
        };

        LIST_PREPEND(peers, w->peers, peer);

        r = hashmap_ensure_put(&w->peers_by_section, &wireguard_peer_hash_ops_by_section, peer->section, peer);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(peer);
        return 0;
}

static int wireguard_set_ipmask_one(NetDev *netdev, sd_netlink_message *message, const WireguardIPmask *mask, uint16_t index) {
        int r;

        assert(message);
        assert(mask);
        assert(index > 0);

        /* This returns 1 on success, 0 on recoverable error, and negative errno on failure. */

        r = sd_netlink_message_open_array(message, index);
        if (r < 0)
                return 0;

        r = sd_netlink_message_append_u16(message, WGALLOWEDIP_A_FAMILY, mask->family);
        if (r < 0)
                goto cancel;

        r = netlink_message_append_in_addr_union(message, WGALLOWEDIP_A_IPADDR, mask->family, &mask->ip);
        if (r < 0)
                goto cancel;

        r = sd_netlink_message_append_u8(message, WGALLOWEDIP_A_CIDR_MASK, mask->cidr);
        if (r < 0)
                goto cancel;

        r = sd_netlink_message_close_container(message);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not add wireguard allowed ip: %m");

        return 1;

cancel:
        r = sd_netlink_message_cancel_array(message);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not cancel wireguard allowed ip message attribute: %m");

        return 0;
}

static int wireguard_set_peer_one(NetDev *netdev, sd_netlink_message *message, const WireguardPeer *peer, uint16_t index, WireguardIPmask **mask_start) {
        WireguardIPmask *start, *last = NULL;
        uint16_t j = 0;
        int r;

        assert(message);
        assert(peer);
        assert(index > 0);
        assert(mask_start);

        /* This returns 1 on success, 0 on recoverable error, and negative errno on failure. */

        start = *mask_start ?: peer->ipmasks;

        r = sd_netlink_message_open_array(message, index);
        if (r < 0)
                return 0;

        r = sd_netlink_message_append_data(message, WGPEER_A_PUBLIC_KEY, &peer->public_key, sizeof(peer->public_key));
        if (r < 0)
                goto cancel;

        if (!*mask_start) {
                r = sd_netlink_message_append_data(message, WGPEER_A_PRESHARED_KEY, &peer->preshared_key, WG_KEY_LEN);
                if (r < 0)
                        goto cancel;

                r = sd_netlink_message_append_u32(message, WGPEER_A_FLAGS, peer->flags);
                if (r < 0)
                        goto cancel;

                if (netdev->kind == NETDEV_KIND_AMNEZIAWG)
                        r = sd_netlink_message_append_u32(message, AWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
                                                         (uint32_t) peer->persistent_keepalive_interval_max << 16 |
                                                         peer->persistent_keepalive_interval);
                else
                        r = sd_netlink_message_append_u16(message, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
                                                         peer->persistent_keepalive_interval);
                if (r < 0)
                        goto cancel;

                if (IN_SET(peer->endpoint.sa.sa_family, AF_INET, AF_INET6)) {
                        r = netlink_message_append_sockaddr_union(message, WGPEER_A_ENDPOINT, &peer->endpoint);
                        if (r < 0)
                                goto cancel;
                }
        }

        r = sd_netlink_message_open_container(message, WGPEER_A_ALLOWEDIPS);
        if (r < 0)
                goto cancel;

        LIST_FOREACH(ipmasks, mask, start) {
                r = wireguard_set_ipmask_one(netdev, message, mask, ++j);
                if (r < 0)
                        return r;
                if (r == 0) {
                        last = mask;
                        break;
                }
        }

        r = sd_netlink_message_close_container(message);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not add wireguard allowed ip: %m");

        r = sd_netlink_message_close_container(message);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not add wireguard peer: %m");

        *mask_start = last; /* Start next cycle from this mask. */
        return !last;

cancel:
        r = sd_netlink_message_cancel_array(message);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not cancel wireguard peers: %m");

        return 0;
}

static int amneziawg_append_parameters(Wireguard *w, sd_netlink_message *message) {
        int r;

        for (unsigned i = AWGDEVICE_A_JC; i <= AWGDEVICE_A_MAX; i++) {
                if (i == AWGDEVICE_A_PEER || (i >= AWGDEVICE_A_I1 && i <= AWGDEVICE_A_HEADER_PROTECTION_KEY))
                        continue;

                uint64_t value = w->amnezia_parameters[i];

                if (i >= AWGDEVICE_A_H1 && i <= AWGDEVICE_A_H4)
                        r = sd_netlink_message_append_u64(message, i, value);
                else if (IN_SET(i, AWGDEVICE_A_RANDOM_TRAILERS, AWGDEVICE_A_DISABLE_COOKIES))
                        r = sd_netlink_message_append_u8(message, i, value);
                else if (i >= AWGDEVICE_A_CONTENT_PADDING_ADDITION && i <= AWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS)
                        r = sd_netlink_message_append_u32(message, i, value);
                else
                        r = sd_netlink_message_append_u16(message, i, value);
                if (r < 0)
                        return r;
        }

        if (w->header_protection_key_set) {
                r = sd_netlink_message_append_data(message, AWGDEVICE_A_HEADER_PROTECTION_KEY,
                                                   w->header_protection_key, sizeof(w->header_protection_key));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int wireguard_set_interface_handler(sd_netlink *rtnl, sd_netlink_message *message, NetDev *netdev) {
        int r;

        if (!netdev_is_managed(netdev))
                return 0;

        r = sd_netlink_message_get_errno(message);
        if (r < 0) {
                log_netdev_warning_errno(netdev, r, "Failed to configure %s interface: %m",
                                         netdev_kind_to_string(netdev->kind));
                netdev_enter_failed(netdev);
        }

        return 0;
}

static int amneziawg_set_signatures(Wireguard *w) {
        NetDev *netdev = NETDEV(w);
        int r;

        /* Send each CPS string separately, as their combined size may exceed the message size limit. */
        FOREACH_ELEMENT(signature, w->amnezia_signatures) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;

                r = sd_genl_message_new(netdev->manager->genl, AWG_GENL_NAME, AWG_CMD_SET_DEVICE, &message);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_string(message, AWGDEVICE_A_IFNAME, netdev->ifname);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_string(message, AWGDEVICE_A_I1 + (signature - w->amnezia_signatures),
                                                      *signature ?: "");
                if (r < 0)
                        return r;

                r = netlink_call_async(netdev->manager->genl, NULL, message, wireguard_set_interface_handler,
                                       netdev_destroy_callback, netdev);
                if (r < 0)
                        return r;

                netdev_ref(netdev);
        }

        return 0;
}

static int wireguard_set_interface(NetDev *netdev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        WireguardIPmask *mask_start = NULL;
        bool sent_once = false;
        Wireguard *w = WIREGUARD(netdev);
        int r;

        if (!netdev_is_managed(netdev))
                return 0; /* Already detached, due to e.g. reloading .netdev files. */

        if (netdev->kind == NETDEV_KIND_AMNEZIAWG) {
                r = amneziawg_set_signatures(w);
                if (r == -EPROTONOSUPPORT)
                        return log_netdev_error_errno(netdev, r,
                                                     "Unsupported AmneziaWG kernel interface version, requires version %d.",
                                                     AWG_GENL_VERSION);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not set AmneziaWG signatures: %m");
        }

        for (WireguardPeer *peer_start = w->peers; peer_start || !sent_once; ) {
                uint16_t i = 0;

                message = sd_netlink_message_unref(message);

                r = sd_genl_message_new(netdev->manager->genl,
                                        netdev->kind == NETDEV_KIND_AMNEZIAWG ? AWG_GENL_NAME : WG_GENL_NAME,
                                        WG_CMD_SET_DEVICE, &message);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Failed to allocate generic netlink message: %m");

                r = sd_netlink_message_append_string(message, WGDEVICE_A_IFNAME, netdev->ifname);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append wireguard interface name: %m");

                if (!sent_once) {
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

                        if (netdev->kind == NETDEV_KIND_AMNEZIAWG) {
                                r = amneziawg_append_parameters(w, message);
                                if (r < 0)
                                        return log_netdev_error_errno(netdev, r, "Could not append AmneziaWG parameters: %m");
                        }
                }

                r = sd_netlink_message_open_container(message, WGDEVICE_A_PEERS);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append wireguard peer attributes: %m");

                WireguardPeer *peer_last = NULL;
                LIST_FOREACH(peers, peer, peer_start) {
                        r = wireguard_set_peer_one(netdev, message, peer, ++i, &mask_start);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                peer_last = peer;
                                break;
                        }
                }
                peer_start = peer_last; /* Start next cycle from this peer. */

                r = sd_netlink_message_close_container(message);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not close wireguard container: %m");

                r = netlink_call_async(netdev->manager->genl, NULL, message, wireguard_set_interface_handler,
                                       netdev_destroy_callback, netdev);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not set wireguard device: %m");

                netdev_ref(netdev);
                sent_once = true;
        }

        return 0;
}

static int on_resolve_retry(sd_event_source *s, usec_t usec, void *userdata) {
        WireguardPeer *peer = ASSERT_PTR(userdata);
        NetDev *netdev;

        assert(peer->wireguard);

        netdev = NETDEV(peer->wireguard);

        if (!netdev_is_managed(netdev))
                return 0;

        peer->resolve_query = sd_resolve_query_unref(peer->resolve_query);

        (void) peer_resolve_endpoint(peer);
        return 0;
}

static usec_t peer_next_resolve_usec(WireguardPeer *peer) {
        usec_t usec;

        /* Given the number of retries this function will return an exponential increasing amount of
         * milliseconds to wait starting at 200ms and capped at 25 seconds. */

        assert(peer);

        usec = (2 << MIN(peer->n_retries, 7U)) * 100 * USEC_PER_MSEC;

        return random_u64_range(usec / 10) + usec * 9 / 10;
}

static int wireguard_peer_resolve_handler(
              sd_resolve_query *q,
              int ret,
              const struct addrinfo *ai,
              void *userdata) {

        WireguardPeer *peer = ASSERT_PTR(userdata);
        NetDev *netdev;
        int r;

        assert(peer->wireguard);

        netdev = NETDEV(peer->wireguard);

        if (!netdev_is_managed(netdev))
                return 0;

        if (ret != 0) {
                log_netdev_warning(netdev, "Failed to resolve host '%s:%s', ignoring: %s",
                                   peer->endpoint_host, peer->endpoint_port, gai_strerror(ret));
                peer->n_retries++;

        } else {
                bool found = false;
                for (; ai; ai = ai->ai_next) {
                        if (!IN_SET(ai->ai_family, AF_INET, AF_INET6))
                                continue;

                        if (ai->ai_addrlen != (ai->ai_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))
                                continue;

                        memcpy(&peer->endpoint, ai->ai_addr, ai->ai_addrlen);
                        r = wireguard_set_interface(netdev);
                        if (r < 0)
                                netdev_enter_failed(netdev);
                        peer->n_retries = 0;
                        found = true;
                        break;
                }

                if (!found) {
                        log_netdev_warning(netdev, "Neither IPv4 nor IPv6 address found for peer endpoint %s:%s, ignoring the endpoint.",
                                           peer->endpoint_host, peer->endpoint_port);
                        peer->n_retries++;
                }
        }

        if (peer->n_retries > 0) {
                r = event_reset_time_relative(netdev->manager->event,
                                              &peer->resolve_retry_event_source,
                                              CLOCK_BOOTTIME,
                                              peer_next_resolve_usec(peer), /* accuracy= */ 0,
                                              on_resolve_retry, peer, /* priority= */ 0, "wireguard-resolve-retry", /* force_reset= */ true);
                if (r < 0)
                        log_netdev_warning_errno(netdev, r, "Could not arm resolve retry handler for endpoint %s:%s, ignoring: %m",
                                                 peer->endpoint_host, peer->endpoint_port);
        }

        wireguard_resolve_endpoints(netdev);
        return 0;
}

static int peer_resolve_endpoint(WireguardPeer *peer) {
        static const struct addrinfo hints = {
                .ai_family = AF_UNSPEC,
                .ai_socktype = SOCK_DGRAM,
                .ai_protocol = IPPROTO_UDP
        };
        NetDev *netdev;
        int r;

        assert(peer);
        assert(peer->wireguard);

        netdev = NETDEV(peer->wireguard);

        if (!netdev_is_managed(netdev))
                return 0; /* Already detached, due to e.g. reloading .netdev files. */

        if (!peer->endpoint_host || !peer->endpoint_port)
                /* Not necessary to resolve the endpoint. */
                return 0;

        if (sd_event_source_get_enabled(peer->resolve_retry_event_source, /* ret= */ NULL) > 0)
                /* Timer event source is enabled. The endpoint will be resolved later. */
                return 0;

        if (peer->resolve_query)
                /* Being resolved, or already resolved. */
                return 0;

        r = sd_resolve_getaddrinfo(netdev->manager->resolve,
                                   &peer->resolve_query,
                                   peer->endpoint_host,
                                   peer->endpoint_port,
                                   &hints,
                                   wireguard_peer_resolve_handler,
                                   peer);
        if (r < 0)
                return log_netdev_full_errno(netdev, r == -ENOBUFS ? LOG_DEBUG : LOG_WARNING, r,
                                             "Failed to create endpoint resolver for %s:%s, ignoring: %m",
                                             peer->endpoint_host, peer->endpoint_port);

        return 0;
}

static void wireguard_resolve_endpoints(NetDev *netdev) {
        Wireguard *w = WIREGUARD(netdev);

        LIST_FOREACH(peers, peer, w->peers)
                if (peer_resolve_endpoint(peer) == -ENOBUFS)
                        /* Too many requests. Let's resolve remaining endpoints later. */
                        break;
}

static int netdev_wireguard_post_create(NetDev *netdev, Link *link) {
        int r;

        assert(WIREGUARD(netdev));

        r = wireguard_set_interface(netdev);
        if (r < 0) {
                netdev_enter_failed(netdev);
                return r;
        }

        wireguard_resolve_endpoints(netdev);
        return 0;
}

int config_parse_wireguard_listen_port(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint16_t *s = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (isempty(rvalue) || streq(rvalue, "auto")) {
                *s = 0;
                return 0;
        }

        r = parse_ip_port(rvalue, s);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid port specification, ignoring assignment: %s", rvalue);
                return 0;
        }

        return 0;
}

static int wireguard_decode_key_and_warn(
                const char *rvalue,
                uint8_t ret[static WG_KEY_LEN],
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        _cleanup_(erase_and_freep) void *key = NULL;
        _cleanup_(erase_and_freep) char *cred = NULL;
        const char *cred_name;
        size_t len;
        int r;

        assert(rvalue);
        assert(ret);
        assert(filename);
        assert(lvalue);

        if (isempty(rvalue)) {
                memzero(ret, WG_KEY_LEN);
                return 1;
        }

        cred_name = startswith(rvalue, "@");
        if (cred_name) {
                r = read_credential(cred_name, (void**) &cred, /* ret_size= */ NULL);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to read credential for wireguard key (%s=), ignoring assignment: %m",
                                   lvalue);
                        return 0;
                }

        } else if (!streq(lvalue, "PublicKey"))
                (void) warn_file_is_world_accessible(filename, /* st= */ NULL, unit, line);

        r = unbase64mem_full(cred ?: rvalue, SIZE_MAX, /* secure= */ true, &key, &len);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, "(secret)");
        if (len != WG_KEY_LEN) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Wireguard key provided by %s= has invalid length (%zu bytes), ignoring assignment.",
                           lvalue, len);
                return 0;
        }

        memcpy(ret, key, WG_KEY_LEN);
        return 1;
}

int config_parse_wireguard_private_key(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Wireguard *w = WIREGUARD(data);
        int r;

        r = wireguard_decode_key_and_warn(rvalue,
                                          streq(lvalue, "HeaderProtectionKey") ? w->header_protection_key : w->private_key,
                                          unit, filename, line, lvalue);
        if (r > 0 && streq(lvalue, "HeaderProtectionKey"))
                w->header_protection_key_set = !isempty(rvalue);

        return r;
}

int config_parse_wireguard_private_key_file(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Wireguard *w = WIREGUARD(data);
        _cleanup_free_ char *path = NULL;
        char **key_file = streq(lvalue, "HeaderProtectionKeyFile") ? &w->header_protection_key_file : &w->private_key_file;

        if (isempty(rvalue)) {
                *key_file = mfree(*key_file);
                return 0;
        }

        path = strdup(rvalue);
        if (!path)
                return log_oom();

        if (path_simplify_and_warn(path, PATH_CHECK_ABSOLUTE|PATH_CHECK_NON_API_VFS, unit, filename, line, lvalue) < 0)
                return 0;

        return free_and_replace(*key_file, path);
}

int config_parse_amneziawg_parameter(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Wireguard *w = WIREGUARD(data);
        unsigned lower, upper;
        uint64_t value;
        int r;

        assert(ltype >= AWGDEVICE_A_JC && ltype <= AWGDEVICE_A_MAX);

        if (isempty(rvalue)) {
                unsigned h = ltype - AWGDEVICE_A_H1 + 1;

                w->amnezia_parameters[ltype] = ltype >= AWGDEVICE_A_H1 && ltype <= AWGDEVICE_A_H4 ?
                        (uint64_t) h << 32 | h : 0;
                return 0;
        }

        if (IN_SET(ltype, AWGDEVICE_A_RANDOM_TRAILERS, AWGDEVICE_A_DISABLE_COOKIES)) {
                r = parse_boolean(rvalue);
                if (r < 0)
                        goto invalid;
                value = r;
        } else if ((ltype >= AWGDEVICE_A_H1 && ltype <= AWGDEVICE_A_H4) ||
                   (ltype >= AWGDEVICE_A_CONTENT_PADDING_ADDITION && ltype <= AWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS)) {
                r = parse_range(rvalue, &lower, &upper);
                if (r < 0)
                        goto invalid;
                if (lower > upper || (ltype >= AWGDEVICE_A_CONTENT_PADDING_ADDITION && upper > UINT16_MAX)) {
                        r = -ERANGE;
                        goto invalid;
                }

                value = (uint64_t) upper << (ltype >= AWGDEVICE_A_H1 && ltype <= AWGDEVICE_A_H4 ? 32 : 16) | lower;
        } else {
                uint16_t n;

                r = safe_atou16(rvalue, &n);
                if (r < 0)
                        goto invalid;
                value = n;
        }

        w->amnezia_parameters[ltype] = value;
        return 0;

invalid:
        log_syntax(unit, LOG_WARNING, filename, line, r,
                   "Invalid %s= value, ignoring assignment: %s", lvalue, rvalue);
        return 0;
}

int config_parse_wireguard_peer_key(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Wireguard *w = WIREGUARD(data);
        _cleanup_(wireguard_peer_free_or_set_invalidp) WireguardPeer *peer = NULL;
        int r;

        r = wireguard_peer_new_static(w, filename, section_line, &peer);
        if (r < 0)
                return log_oom();

        r = wireguard_decode_key_and_warn(rvalue,
                                          streq(lvalue, "PublicKey") ? peer->public_key : peer->preshared_key,
                                          unit, filename, line, lvalue);
        if (r < 0)
                return r;

        TAKE_PTR(peer);
        return 0;
}

int config_parse_wireguard_peer_key_file(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Wireguard *w = WIREGUARD(data);
        _cleanup_(wireguard_peer_free_or_set_invalidp) WireguardPeer *peer = NULL;
        _cleanup_free_ char *path = NULL;
        char **key_file;
        int r;

        assert(filename);
        assert(lvalue);

        r = wireguard_peer_new_static(w, filename, section_line, &peer);
        if (r < 0)
                return log_oom();

        if (streq(lvalue, "PublicKeyFile"))
                key_file = &peer->public_key_file;
        else if (streq(lvalue, "PresharedKeyFile"))
                key_file = &peer->preshared_key_file;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *key_file = mfree(*key_file);
                TAKE_PTR(peer);
                return 0;
        }

        path = strdup(rvalue);
        if (!path)
                return log_oom();

        if (path_simplify_and_warn(path, PATH_CHECK_ABSOLUTE|PATH_CHECK_NON_API_VFS, unit, filename, line, lvalue) < 0)
                return 0;

        free_and_replace(*key_file, path);
        TAKE_PTR(peer);
        return 0;
}

int config_parse_wireguard_allowed_ips(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(rvalue);

        Wireguard *w = WIREGUARD(data);
        _cleanup_(wireguard_peer_free_or_set_invalidp) WireguardPeer *peer = NULL;
        union in_addr_union addr;
        unsigned char prefixlen;
        int r, family;
        WireguardIPmask *ipmask;

        r = wireguard_peer_new_static(w, filename, section_line, &peer);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                wireguard_peer_clear_ipmasks(peer);
                TAKE_PTR(peer);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                union in_addr_union masked;

                r = extract_first_word(&p, &word, "," WHITESPACE, /* flags= */ 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to split allowed ips \"%s\" option: %m", rvalue);
                        break;
                }

                r = in_addr_prefix_from_string_auto(word, &family, &addr, &prefixlen);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Network address is invalid, ignoring assignment: %s", word);
                        continue;
                }

                masked = addr;
                assert_se(in_addr_mask(family, &masked, prefixlen) >= 0);
                if (!in_addr_equal(family, &masked, &addr))
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Specified address '%s' is not properly masked, assuming '%s'.",
                                   word,
                                   IN_ADDR_PREFIX_TO_STRING(family, &masked, prefixlen));

                ipmask = new(WireguardIPmask, 1);
                if (!ipmask)
                        return log_oom();

                *ipmask = (WireguardIPmask) {
                        .family = family,
                        .ip = masked,
                        .cidr = prefixlen,
                };

                LIST_PREPEND(ipmasks, peer->ipmasks, ipmask);
        }

        TAKE_PTR(peer);
        return 0;
}

int config_parse_wireguard_endpoint(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Wireguard *w = WIREGUARD(userdata);
        _cleanup_(wireguard_peer_free_or_set_invalidp) WireguardPeer *peer = NULL;
        _cleanup_free_ char *cred = NULL;
        const char *cred_name, *endpoint;
        uint16_t port;
        int r;

        assert(filename);
        assert(rvalue);

        r = wireguard_peer_new_static(w, filename, section_line, &peer);
        if (r < 0)
                return log_oom();

        cred_name = startswith(rvalue, "@");
        if (cred_name) {
                r = read_credential(cred_name, (void**) &cred, /* ret_size= */ NULL);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to read credential for wireguard endpoint, ignoring assignment: %m");
                        return 0;
                }

                endpoint = strstrip(cred);
        } else
                endpoint = rvalue;

        union in_addr_union addr;
        int family;

        r = in_addr_port_ifindex_name_from_string_auto(endpoint, &family, &addr, &port, /* ret_ifindex= */ NULL, /* ret_server_name= */ NULL);
        if (r >= 0) {
                if (family == AF_INET)
                        peer->endpoint.in = (struct sockaddr_in) {
                                .sin_family = AF_INET,
                                .sin_addr = addr.in,
                                .sin_port = htobe16(port),
                        };
                else if (family == AF_INET6)
                        peer->endpoint.in6 = (struct sockaddr_in6) {
                                .sin6_family = AF_INET6,
                                .sin6_addr = addr.in6,
                                .sin6_port = htobe16(port),
                        };
                else
                        assert_not_reached();

                peer->endpoint_host = mfree(peer->endpoint_host);
                peer->endpoint_port = mfree(peer->endpoint_port);

                TAKE_PTR(peer);
                return 0;
        }

        _cleanup_free_ char *host = NULL;
        const char *p;

        p = strrchr(endpoint, ':');
        if (!p) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Unable to find port of endpoint, ignoring assignment: %s",
                           rvalue); /* We log the original assignment instead of resolved credential here,
                                       as the latter might be previously encrypted and we'd expose them in
                                       unprotected logs otherwise. */
                return 0;
        }

        host = strndup(endpoint, p - endpoint);
        if (!host)
                return log_oom();
        p++;

        if (!dns_name_is_valid(host)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid domain name of endpoint, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        r = parse_ip_port(p, &port);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid port of endpoint, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        peer->endpoint = (union sockaddr_union) {};

        free_and_replace(peer->endpoint_host, host);

        r = free_and_strdup(&peer->endpoint_port, p);
        if (r < 0)
                return log_oom();

        TAKE_PTR(peer); /* The peer may already have been in the hash map, that is fine too. */
        return 0;
}

int config_parse_wireguard_keepalive(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(rvalue);

        Wireguard *w = WIREGUARD(data);
        _cleanup_(wireguard_peer_free_or_set_invalidp) WireguardPeer *peer = NULL;
        unsigned lower = 0, upper = 0;
        int r;

        r = wireguard_peer_new_static(w, filename, section_line, &peer);
        if (r < 0)
                return log_oom();

        if (!streq(rvalue, "off")) {
                if (NETDEV(w)->kind == NETDEV_KIND_AMNEZIAWG)
                        r = parse_range(rvalue, &lower, &upper);
                else {
                        uint16_t keepalive;

                        r = safe_atou16(rvalue, &keepalive);
                        if (r >= 0)
                                lower = upper = keepalive;
                }
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (lower > upper || upper > UINT16_MAX)
                        return log_syntax_parse_error(unit, filename, line, -ERANGE, lvalue, rvalue);
        }

        peer->persistent_keepalive_interval = lower;
        peer->persistent_keepalive_interval_max = upper;

        TAKE_PTR(peer);
        return 0;
}

int config_parse_wireguard_route_table(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        NetDev *netdev = ASSERT_PTR(userdata);
        uint32_t *table = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue) || parse_boolean(rvalue) == 0) {
                *table = 0; /* Disabled. */
                return 0;
        }

        r = manager_get_route_table_from_string(netdev->manager, rvalue, table);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 0;
}

int config_parse_wireguard_peer_route_table(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Wireguard *w = WIREGUARD(userdata);
        _cleanup_(wireguard_peer_free_or_set_invalidp) WireguardPeer *peer = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(NETDEV(w)->manager);

        r = wireguard_peer_new_static(w, filename, section_line, &peer);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                peer->route_table_set = false; /* Use the table specified in [WireGuard] section. */
                TAKE_PTR(peer);
                return 0;
        }

        if (parse_boolean(rvalue) == 0) {
                peer->route_table = 0; /* Disabled. */
                peer->route_table_set = true;
                TAKE_PTR(peer);
                return 0;
        }

        r = manager_get_route_table_from_string(NETDEV(w)->manager, rvalue, &peer->route_table);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        peer->route_table_set = true;
        TAKE_PTR(peer);
        return 0;
}

int config_parse_wireguard_route_priority(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t *priority = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *priority = 0;
                return 0;
        }

        r = safe_atou32(rvalue, priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse route priority \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_wireguard_peer_route_priority(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(wireguard_peer_free_or_set_invalidp) WireguardPeer *peer = NULL;
        Wireguard *w;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        w = WIREGUARD(userdata);
        assert(w);

        r = wireguard_peer_new_static(w, filename, section_line, &peer);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                peer->route_priority_set = false; /* Use the priority specified in [WireGuard] section. */
                TAKE_PTR(peer);
                return 0;
        }

        r = safe_atou32(rvalue, &peer->route_priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse route priority \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        peer->route_priority_set = true;
        TAKE_PTR(peer);
        return 0;
}

static void wireguard_init(NetDev *netdev) {
        Wireguard *w = WIREGUARD(netdev);

        w->flags = WGDEVICE_F_REPLACE_PEERS;
        for (unsigned i = 0; i < 4; i++)
                w->amnezia_parameters[AWGDEVICE_A_H1 + i] = (uint64_t) (i + 1) << 32 | (i + 1);
}

static void wireguard_done(NetDev *netdev) {
        Wireguard *w = WIREGUARD(netdev);

        explicit_bzero_safe(w->private_key, WG_KEY_LEN);
        free(w->private_key_file);
        explicit_bzero_safe(w->header_protection_key, sizeof(w->header_protection_key));
        free(w->header_protection_key_file);
        FOREACH_ELEMENT(signature, w->amnezia_signatures)
                free(*signature);

        hashmap_free(w->peers_by_section);

        set_free(w->routes);
}

static int wireguard_read_key_file(const char *filename, uint8_t dest[static WG_KEY_LEN]) {
        _cleanup_(erase_and_freep) char *key = NULL;
        size_t key_len;
        int r;

        if (!filename)
                return 0;

        assert(dest);

        r = read_full_file_full(
                        AT_FDCWD, filename, UINT64_MAX, WG_KEY_LEN,
                        READ_FULL_FILE_SECURE |
                        READ_FULL_FILE_UNBASE64 |
                        READ_FULL_FILE_WARN_WORLD_READABLE |
                        READ_FULL_FILE_CONNECT_SOCKET |
                        READ_FULL_FILE_FAIL_WHEN_LARGER,
                        /* bind_name= */ NULL, &key, &key_len);
        if (r < 0)
                return r;

        if (key_len != WG_KEY_LEN)
                return -EINVAL;

        memcpy(dest, key, WG_KEY_LEN);
        return 0;
}

static int wireguard_peer_verify(WireguardPeer *peer) {
        NetDev *netdev = NETDEV(peer->wireguard);
        int r;

        if (section_is_invalid(peer->section))
                return -EINVAL;

        r = wireguard_read_key_file(peer->public_key_file, peer->public_key);
        if (r < 0)
                return log_netdev_error_errno(netdev, r,
                                              "%s: Failed to read public key from '%s'. "
                                              "Ignoring [WireGuardPeer] section from line %u.",
                                              peer->section->filename, peer->public_key_file,
                                              peer->section->line);

        if (eqzero(peer->public_key))
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: WireGuardPeer section without PublicKey= configured. "
                                              "Ignoring [WireGuardPeer] section from line %u.",
                                              peer->section->filename, peer->section->line);

        r = wireguard_read_key_file(peer->preshared_key_file, peer->preshared_key);
        if (r < 0)
                return log_netdev_error_errno(netdev, r,
                                              "%s: Failed to read preshared key from '%s'. "
                                              "Ignoring [WireGuardPeer] section from line %u.",
                                              peer->section->filename, peer->preshared_key_file,
                                              peer->section->line);

        return 0;
}

static int wireguard_read_default_key_cred(NetDev *netdev, const char *filename) {
        Wireguard *w = WIREGUARD(netdev);
        _cleanup_free_ char *config_name = NULL;
        int r;

        assert(filename);

        r = path_extract_filename(filename, &config_name);
        if (r < 0)
                return log_netdev_error_errno(netdev, r,
                                              "%s: Failed to extract config name, ignoring network device: %m",
                                              filename);

        char *p = endswith(config_name, ".netdev");
        if (!p)
                /* Fuzzer run? Then we just ignore this device. */
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: Invalid netdev config name, refusing default key lookup.",
                                              filename);
        *p = '\0';

        _cleanup_(erase_and_freep) char *cred = NULL;

        r = read_credential(strjoina("network.wireguard.private.", config_name), (void**) &cred, /* ret_size= */ NULL);
        if (r < 0)
                return log_netdev_error_errno(netdev, r,
                                              "%s: No private key specified and default key isn't available, "
                                              "ignoring network device: %m",
                                              filename);

        _cleanup_(erase_and_freep) void *key = NULL;
        size_t len;

        r = unbase64mem_full(cred, SIZE_MAX, /* secure= */ true, &key, &len);
        if (r < 0)
                return log_netdev_error_errno(netdev, r,
                                              "%s: No private key specified and default key cannot be parsed, "
                                              "ignoring network device: %m",
                                              filename);
        if (len != WG_KEY_LEN || memeqzero(key, len))
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: No private key specified and default key is invalid. "
                                              "Ignoring network device.",
                                              filename);

        memcpy(w->private_key, key, WG_KEY_LEN);
        return 0;
}

static int amneziawg_verify(Wireguard *w) {
        NetDev *netdev = NETDEV(w);
        uint64_t headers[4];
        int r;

        r = wireguard_read_key_file(w->header_protection_key_file, w->header_protection_key);
        if (r < 0)
                return log_netdev_error_errno(netdev, r,
                                              "Failed to read header protection key from '%s', ignoring network device: %m",
                                              w->header_protection_key_file);
        if (w->header_protection_key_file)
                w->header_protection_key_set = true;

        if (w->amnezia_parameters[AWGDEVICE_A_JMIN] > w->amnezia_parameters[AWGDEVICE_A_JMAX])
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "Jmin= exceeds Jmax=, ignoring network device.");

        FOREACH_ELEMENT(header, headers) {
                unsigned i = header - headers;

                *header = w->amnezia_parameters[AWGDEVICE_A_H1 + i];
        }

        for (unsigned i = 0; i < ELEMENTSOF(headers); i++)
                for (unsigned j = i + 1; j < ELEMENTSOF(headers); j++)
                        if ((uint32_t) headers[i] <= headers[j] >> 32 && (uint32_t) headers[j] <= headers[i] >> 32)
                                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                              "H%u= and H%u= overlap, ignoring network device.", i + 1, j + 1);

        if (w->header_protection_key_set) {
                int i;

                FOREACH_ARGUMENT(i, AWGDEVICE_A_S1, AWGDEVICE_A_S2, AWGDEVICE_A_S3, AWGDEVICE_A_S4)
                        if (w->amnezia_parameters[i] < 12)
                                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                              "HeaderProtectionKey= requires S1= through S4= to be at least 12, ignoring network device.");
        }

        return 0;
}

static int wireguard_verify(NetDev *netdev, const char *filename) {
        Wireguard *w = WIREGUARD(netdev);
        int r;

        r = wireguard_read_key_file(w->private_key_file, w->private_key);
        if (r < 0)
                return log_netdev_error_errno(netdev, r,
                                              "Failed to read private key from '%s', ignoring network device: %m",
                                              w->private_key_file);

        if (eqzero(w->private_key)) {
                r = wireguard_read_default_key_cred(netdev, filename);
                if (r < 0)
                        return r;
        }

        if (netdev->kind == NETDEV_KIND_AMNEZIAWG) {
                r = amneziawg_verify(w);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(peers, peer, w->peers) {
                if (wireguard_peer_verify(peer) < 0) {
                        wireguard_peer_free(peer);
                        continue;
                }

                if ((peer->route_table_set ? peer->route_table : w->route_table) == 0)
                        continue;

                LIST_FOREACH(ipmasks, ipmask, peer->ipmasks) {
                        _cleanup_(route_unrefp) Route *route = NULL;

                        r = route_new(&route);
                        if (r < 0)
                                return log_oom();

                        /* For route_section_verify() below. */
                        r = config_section_new(peer->section->filename, peer->section->line, &route->section);
                        if (r < 0)
                                return log_oom();

                        route->source = NETWORK_CONFIG_SOURCE_STATIC;
                        route->family = ipmask->family;
                        route->dst = ipmask->ip;
                        route->dst_prefixlen = ipmask->cidr;
                        route->protocol = RTPROT_STATIC;
                        route->protocol_set = true;
                        route->table = peer->route_table_set ? peer->route_table : w->route_table;
                        route->table_set = true;
                        route->priority = peer->route_priority_set ? peer->route_priority : w->route_priority;
                        route->priority_set = true;

                        if (route_section_verify(route) < 0)
                                continue;

                        r = set_ensure_put(&w->routes, &route_hash_ops, route);
                        if (r < 0)
                                return log_oom();
                        if (r == 0)
                                continue;

                        route->wireguard = w;
                        TAKE_PTR(route);
                }
        }

        return 0;
}

const NetDevVTable wireguard_vtable = {
        .object_size = sizeof(Wireguard),
        .sections = NETDEV_COMMON_SECTIONS "WireGuard\0WireGuardPeer\0",
        .post_create = netdev_wireguard_post_create,
        .init = wireguard_init,
        .done = wireguard_done,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = wireguard_verify,
        .iftype = ARPHRD_NONE,
        .keep_existing = true,
};

const NetDevVTable amneziawg_vtable = {
        .object_size = sizeof(Wireguard),
        .sections = NETDEV_COMMON_SECTIONS "WireGuard\0WireGuardPeer\0AmneziaWG\0",
        .post_create = netdev_wireguard_post_create,
        .init = wireguard_init,
        .done = wireguard_done,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = wireguard_verify,
        .iftype = ARPHRD_NONE,
        .keep_existing = true,
};
