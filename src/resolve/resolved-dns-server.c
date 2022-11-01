/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-messages.h"

#include "alloc-util.h"
#include "resolved-bus.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stub.h"
#include "resolved-manager.h"
#include "resolved-resolv-conf.h"
#include "siphash24.h"
#include "string-table.h"
#include "string-util.h"

/* The amount of time to wait before retrying with a full feature set */
#define DNS_SERVER_FEATURE_GRACE_PERIOD_MAX_USEC (6 * USEC_PER_HOUR)
#define DNS_SERVER_FEATURE_GRACE_PERIOD_MIN_USEC (5 * USEC_PER_MINUTE)

/* The number of times we will attempt a certain feature set before degrading */
#define DNS_SERVER_FEATURE_RETRY_ATTEMPTS 3

int dns_server_new(
                Manager *m,
                DnsServer **ret,
                DnsServerType type,
                Link *l,
                int family,
                const union in_addr_union *in_addr,
                uint16_t port,
                int ifindex,
                const char *server_name) {

        _cleanup_free_ char *name = NULL;
        DnsServer *s;

        assert(m);
        assert((type == DNS_SERVER_LINK) == !!l);
        assert(in_addr);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        if (l) {
                if (l->n_dns_servers >= LINK_DNS_SERVERS_MAX)
                        return -E2BIG;
        } else {
                if (m->n_dns_servers >= MANAGER_DNS_SERVERS_MAX)
                        return -E2BIG;
        }

        if (!isempty(server_name)) {
                name = strdup(server_name);
                if (!name)
                        return -ENOMEM;
        }

        s = new(DnsServer, 1);
        if (!s)
                return -ENOMEM;

        *s = (DnsServer) {
                .n_ref = 1,
                .manager = m,
                .type = type,
                .family = family,
                .address = *in_addr,
                .port = port,
                .ifindex = ifindex,
                .server_name = TAKE_PTR(name),
        };

        dns_server_reset_features(s);

        switch (type) {

        case DNS_SERVER_LINK:
                s->link = l;
                LIST_APPEND(servers, l->dns_servers, s);
                l->n_dns_servers++;
                break;

        case DNS_SERVER_SYSTEM:
                LIST_APPEND(servers, m->dns_servers, s);
                m->n_dns_servers++;
                break;

        case DNS_SERVER_FALLBACK:
                LIST_APPEND(servers, m->fallback_dns_servers, s);
                m->n_dns_servers++;
                break;

        default:
                assert_not_reached();
        }

        s->linked = true;

        /* A new DNS server that isn't fallback is added and the one
         * we used so far was a fallback one? Then let's try to pick
         * the new one */
        if (type != DNS_SERVER_FALLBACK &&
            m->current_dns_server &&
            m->current_dns_server->type == DNS_SERVER_FALLBACK)
                manager_set_dns_server(m, NULL);

        if (ret)
                *ret = s;

        return 0;
}

static DnsServer* dns_server_free(DnsServer *s)  {
        assert(s);

        dns_server_unref_stream(s);

#if ENABLE_DNS_OVER_TLS
        dnstls_server_free(s);
#endif

        free(s->server_string);
        free(s->server_string_full);
        free(s->server_name);
        return mfree(s);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnsServer, dns_server, dns_server_free);

void dns_server_unlink(DnsServer *s) {
        assert(s);
        assert(s->manager);

        /* This removes the specified server from the linked list of
         * servers, but any server might still stay around if it has
         * refs, for example from an ongoing transaction. */

        if (!s->linked)
                return;

        switch (s->type) {

        case DNS_SERVER_LINK:
                assert(s->link);
                assert(s->link->n_dns_servers > 0);
                LIST_REMOVE(servers, s->link->dns_servers, s);
                s->link->n_dns_servers--;
                break;

        case DNS_SERVER_SYSTEM:
                assert(s->manager->n_dns_servers > 0);
                LIST_REMOVE(servers, s->manager->dns_servers, s);
                s->manager->n_dns_servers--;
                break;

        case DNS_SERVER_FALLBACK:
                assert(s->manager->n_dns_servers > 0);
                LIST_REMOVE(servers, s->manager->fallback_dns_servers, s);
                s->manager->n_dns_servers--;
                break;
        default:
                assert_not_reached();
        }

        s->linked = false;

        if (s->link && s->link->current_dns_server == s)
                link_set_dns_server(s->link, NULL);

        if (s->manager->current_dns_server == s)
                manager_set_dns_server(s->manager, NULL);

        /* No need to keep a default stream around anymore */
        dns_server_unref_stream(s);

        dns_server_unref(s);
}

void dns_server_move_back_and_unmark(DnsServer *s) {
        DnsServer *tail;

        assert(s);

        if (!s->marked)
                return;

        s->marked = false;

        if (!s->linked || !s->servers_next)
                return;

        /* Move us to the end of the list, so that the order is
         * strictly kept, if we are not at the end anyway. */

        switch (s->type) {

        case DNS_SERVER_LINK:
                assert(s->link);
                LIST_FIND_TAIL(servers, s, tail);
                LIST_REMOVE(servers, s->link->dns_servers, s);
                LIST_INSERT_AFTER(servers, s->link->dns_servers, tail, s);
                break;

        case DNS_SERVER_SYSTEM:
                LIST_FIND_TAIL(servers, s, tail);
                LIST_REMOVE(servers, s->manager->dns_servers, s);
                LIST_INSERT_AFTER(servers, s->manager->dns_servers, tail, s);
                break;

        case DNS_SERVER_FALLBACK:
                LIST_FIND_TAIL(servers, s, tail);
                LIST_REMOVE(servers, s->manager->fallback_dns_servers, s);
                LIST_INSERT_AFTER(servers, s->manager->fallback_dns_servers, tail, s);
                break;

        default:
                assert_not_reached();
        }
}

static void dns_server_verified(DnsServer *s, DnsServerFeatureLevel level) {
        assert(s);

        if (s->verified_feature_level > level)
                return;

        if (s->verified_feature_level != level) {
                log_debug("Verified we get a response at feature level %s from DNS server %s.",
                          dns_server_feature_level_to_string(level),
                          strna(dns_server_string_full(s)));
                s->verified_feature_level = level;
        }

        assert_se(sd_event_now(s->manager->event, CLOCK_BOOTTIME, &s->verified_usec) >= 0);
}

static void dns_server_reset_counters(DnsServer *s) {
        assert(s);

        s->n_failed_udp = 0;
        s->n_failed_tcp = 0;
        s->n_failed_tls = 0;
        s->packet_truncated = false;
        s->packet_invalid = false;
        s->verified_usec = 0;

        /* Note that we do not reset s->packet_bad_opt and s->packet_rrsig_missing here. We reset them only when the
         * grace period ends, but not when lowering the possible feature level, as a lower level feature level should
         * not make RRSIGs appear or OPT appear, but rather make them disappear. If the reappear anyway, then that's
         * indication for a differently broken OPT/RRSIG implementation, and we really don't want to support that
         * either.
         *
         * This is particularly important to deal with certain Belkin routers which break OPT for certain lookups (A),
         * but pass traffic through for others (AAAA). If we detect the broken behaviour on one lookup we should not
         * re-enable it for another, because we cannot validate things anyway, given that the RRSIG/OPT data will be
         * incomplete. */
}

void dns_server_packet_received(DnsServer *s, int protocol, DnsServerFeatureLevel level, size_t fragsize) {
        assert(s);

        if (protocol == IPPROTO_UDP) {
                if (s->possible_feature_level == level)
                        s->n_failed_udp = 0;
        } else if (protocol == IPPROTO_TCP) {
                if (DNS_SERVER_FEATURE_LEVEL_IS_TLS(level)) {
                        if (s->possible_feature_level == level)
                                s->n_failed_tls = 0;
                } else {
                        if (s->possible_feature_level == level)
                                s->n_failed_tcp = 0;

                        /* Successful TCP connections are only useful to verify the TCP feature level. */
                        level = DNS_SERVER_FEATURE_LEVEL_TCP;
                }
        }

        /* If the RRSIG data is missing, then we can only validate EDNS0 at max */
        if (s->packet_rrsig_missing && level >= DNS_SERVER_FEATURE_LEVEL_DO)
                level = DNS_SERVER_FEATURE_LEVEL_IS_TLS(level) ? DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN : DNS_SERVER_FEATURE_LEVEL_EDNS0;

        /* If the OPT RR got lost, then we can only validate UDP at max */
        if (s->packet_bad_opt && level >= DNS_SERVER_FEATURE_LEVEL_EDNS0)
                level = DNS_SERVER_FEATURE_LEVEL_EDNS0 - 1;

        dns_server_verified(s, level);

        /* Remember the size of the largest UDP packet fragment we received from a server, we know that we
         * can always announce support for packets with at least this size. */
        if (protocol == IPPROTO_UDP && s->received_udp_fragment_max < fragsize)
                s->received_udp_fragment_max = fragsize;
}

void dns_server_packet_lost(DnsServer *s, int protocol, DnsServerFeatureLevel level) {
        assert(s);
        assert(s->manager);

        if (s->possible_feature_level != level)
                return;

        if (protocol == IPPROTO_UDP)
                s->n_failed_udp++;
        else if (protocol == IPPROTO_TCP) {
                if (DNS_SERVER_FEATURE_LEVEL_IS_TLS(level))
                        s->n_failed_tls++;
                else
                        s->n_failed_tcp++;
        }
}

void dns_server_packet_truncated(DnsServer *s, DnsServerFeatureLevel level) {
        assert(s);

        /* Invoked whenever we get a packet with TC bit set. */

        if (s->possible_feature_level != level)
                return;

        s->packet_truncated = true;
}

void dns_server_packet_rrsig_missing(DnsServer *s, DnsServerFeatureLevel level) {
        assert(s);

        if (level < DNS_SERVER_FEATURE_LEVEL_DO)
                return;

        /* If the RRSIG RRs are missing, we have to downgrade what we previously verified */
        if (s->verified_feature_level >= DNS_SERVER_FEATURE_LEVEL_DO)
                s->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_IS_TLS(level) ? DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN : DNS_SERVER_FEATURE_LEVEL_EDNS0;

        s->packet_rrsig_missing = true;
}

void dns_server_packet_bad_opt(DnsServer *s, DnsServerFeatureLevel level) {
        assert(s);

        if (level < DNS_SERVER_FEATURE_LEVEL_EDNS0)
                return;

        /* If the OPT RR got lost, we have to downgrade what we previously verified */
        if (s->verified_feature_level >= DNS_SERVER_FEATURE_LEVEL_EDNS0)
                s->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0-1;

        s->packet_bad_opt = true;
}

void dns_server_packet_rcode_downgrade(DnsServer *s, DnsServerFeatureLevel level) {
        assert(s);

        /* Invoked whenever we got a FORMERR, SERVFAIL or NOTIMP rcode from a server and downgrading the feature level
         * for the transaction made it go away. In this case we immediately downgrade to the feature level that made
         * things work. */

        if (s->verified_feature_level > level)
                s->verified_feature_level = level;

        if (s->possible_feature_level > level) {
                s->possible_feature_level = level;
                dns_server_reset_counters(s);
                log_debug("Downgrading transaction feature level fixed an RCODE error, downgrading server %s too.", strna(dns_server_string_full(s)));
        }
}

void dns_server_packet_invalid(DnsServer *s, DnsServerFeatureLevel level) {
        assert(s);

        /* Invoked whenever we got a packet we couldn't parse at all */

        if (s->possible_feature_level != level)
                return;

        s->packet_invalid = true;
}

void dns_server_packet_do_off(DnsServer *s, DnsServerFeatureLevel level) {
        assert(s);

        /* Invoked whenever the DO flag was not copied from our request to the response. */

        if (s->possible_feature_level != level)
                return;

        s->packet_do_off = true;
}

void dns_server_packet_udp_fragmented(DnsServer *s, size_t fragsize) {
        assert(s);

        /* Invoked whenever we got a fragmented UDP packet. Let's do two things: keep track of the largest
         * fragment we ever received from the server, and remember this, so that we can use it to lower the
         * advertised packet size in EDNS0 */

        if (s->received_udp_fragment_max < fragsize)
                s->received_udp_fragment_max = fragsize;

        s->packet_fragmented = true;
}

static bool dns_server_grace_period_expired(DnsServer *s) {
        usec_t ts;

        assert(s);
        assert(s->manager);

        if (s->verified_usec == 0)
                return false;

        assert_se(sd_event_now(s->manager->event, CLOCK_BOOTTIME, &ts) >= 0);

        if (s->verified_usec + s->features_grace_period_usec > ts)
                return false;

        s->features_grace_period_usec = MIN(s->features_grace_period_usec * 2, DNS_SERVER_FEATURE_GRACE_PERIOD_MAX_USEC);

        return true;
}

DnsServerFeatureLevel dns_server_possible_feature_level(DnsServer *s) {
        DnsServerFeatureLevel best;

        assert(s);

        /* Determine the best feature level we care about. If DNSSEC mode is off there's no point in using anything
         * better than EDNS0, hence don't even try. */
        if (dns_server_get_dnssec_mode(s) != DNSSEC_NO)
                best = dns_server_get_dns_over_tls_mode(s) == DNS_OVER_TLS_NO ?
                        DNS_SERVER_FEATURE_LEVEL_DO :
                        DNS_SERVER_FEATURE_LEVEL_TLS_DO;
        else
                best = dns_server_get_dns_over_tls_mode(s) == DNS_OVER_TLS_NO ?
                        DNS_SERVER_FEATURE_LEVEL_EDNS0 :
                        DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN;

        /* Clamp the feature level the highest level we care about. The DNSSEC mode might have changed since the last
         * time, hence let's downgrade if we are still at a higher level. */
        if (s->possible_feature_level > best)
                s->possible_feature_level = best;

        if (s->possible_feature_level < best && dns_server_grace_period_expired(s)) {

                s->possible_feature_level = best;

                dns_server_reset_counters(s);

                s->packet_bad_opt = false;
                s->packet_rrsig_missing = false;

                log_info("Grace period over, resuming full feature set (%s) for DNS server %s.",
                         dns_server_feature_level_to_string(s->possible_feature_level),
                         strna(dns_server_string_full(s)));

                dns_server_flush_cache(s);

        } else if (s->possible_feature_level <= s->verified_feature_level)
                s->possible_feature_level = s->verified_feature_level;
        else {
                DnsServerFeatureLevel p = s->possible_feature_level;
                int log_level = LOG_WARNING;

                if (s->n_failed_tcp >= DNS_SERVER_FEATURE_RETRY_ATTEMPTS &&
                    s->possible_feature_level == DNS_SERVER_FEATURE_LEVEL_TCP) {

                        /* We are at the TCP (lowest) level, and we tried a couple of TCP connections, and it didn't
                         * work. Upgrade back to UDP again. */
                        log_debug("Reached maximum number of failed TCP connection attempts, trying UDP again...");
                        s->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_UDP;

                } else if (s->n_failed_tls > 0 &&
                           DNS_SERVER_FEATURE_LEVEL_IS_TLS(s->possible_feature_level) &&
                           dns_server_get_dns_over_tls_mode(s) != DNS_OVER_TLS_YES) {

                        /* We tried to connect using DNS-over-TLS, and it didn't work. Downgrade to plaintext UDP
                         * if we don't require DNS-over-TLS */

                        log_debug("Server doesn't support DNS-over-TLS, downgrading protocol...");
                        s->possible_feature_level--;

                } else if (s->packet_invalid &&
                           s->possible_feature_level > DNS_SERVER_FEATURE_LEVEL_UDP &&
                           s->possible_feature_level != DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN) {

                        /* Downgrade from DO to EDNS0 + from EDNS0 to UDP, from TLS+DO to plain TLS. Or in
                         * other words, if we receive a packet we cannot parse jump to the next lower feature
                         * level that actually has an influence on the packet layout (and not just the
                         * transport). */

                        log_debug("Got invalid packet from server, downgrading protocol...");
                        s->possible_feature_level =
                                s->possible_feature_level == DNS_SERVER_FEATURE_LEVEL_TLS_DO  ? DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN :
                                DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(s->possible_feature_level) ? DNS_SERVER_FEATURE_LEVEL_EDNS0 :
                                                                                                DNS_SERVER_FEATURE_LEVEL_UDP;

                } else if (s->packet_bad_opt &&
                           DNS_SERVER_FEATURE_LEVEL_IS_EDNS0(s->possible_feature_level) &&
                           dns_server_get_dnssec_mode(s) != DNSSEC_YES &&
                           dns_server_get_dns_over_tls_mode(s) != DNS_OVER_TLS_YES) {

                        /* A reply to one of our EDNS0 queries didn't carry a valid OPT RR, then downgrade to
                         * below EDNS0 levels. After all, some servers generate different responses with and
                         * without OPT RR in the request. Example:
                         *
                         * https://open.nlnetlabs.nl/pipermail/dnssec-trigger/2014-November/000376.html
                         *
                         * If we are in strict DNSSEC or DoT mode, we don't do this kind of downgrade
                         * however, as both modes imply EDNS0 to work (DNSSEC strictly requires it, and DoT
                         * only in our implementation). */

                        log_debug("Server doesn't support EDNS(0) properly, downgrading feature level...");
                        s->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_UDP;

                        /* Users often don't control the DNS server they use so let's not complain too loudly
                         * when we can't use EDNS because the DNS server doesn't support it. */
                        log_level = LOG_NOTICE;

                } else if (s->packet_do_off &&
                           DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(s->possible_feature_level) &&
                           dns_server_get_dnssec_mode(s) != DNSSEC_YES) {

                        /* The server didn't copy the DO bit from request to response, thus DNSSEC is not
                         * correctly implemented, let's downgrade if that's allowed. */

                        log_debug("Detected server didn't copy DO flag from request to response, downgrading feature level...");
                        s->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_IS_TLS(s->possible_feature_level) ? DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN :
                                                                                                                 DNS_SERVER_FEATURE_LEVEL_EDNS0;

                } else if (s->packet_rrsig_missing &&
                           DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(s->possible_feature_level) &&
                           dns_server_get_dnssec_mode(s) != DNSSEC_YES) {

                        /* RRSIG data was missing on an EDNS0 packet with DO bit set. This means the server
                         * doesn't augment responses with DNSSEC RRs. If so, let's better not ask the server
                         * for it anymore, after all some servers generate different replies depending if an
                         * OPT RR is in the query or not. If we are in strict DNSSEC mode, don't allow such
                         * downgrades however, since a DNSSEC feature level is a requirement for strict
                         * DNSSEC mode. */

                        log_debug("Detected server responses lack RRSIG records, downgrading feature level...");
                        s->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_IS_TLS(s->possible_feature_level) ? DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN :
                                                                                                                 DNS_SERVER_FEATURE_LEVEL_EDNS0;

                } else if (s->n_failed_udp >= DNS_SERVER_FEATURE_RETRY_ATTEMPTS &&
                           DNS_SERVER_FEATURE_LEVEL_IS_UDP(s->possible_feature_level) &&
                           ((s->possible_feature_level != DNS_SERVER_FEATURE_LEVEL_DO) || dns_server_get_dnssec_mode(s) != DNSSEC_YES)) {

                        /* We lost too many UDP packets in a row, and are on an UDP feature level. If the
                         * packets are lost, maybe the server cannot parse them, hence downgrading sounds
                         * like a good idea. We might downgrade all the way down to TCP this way.
                         *
                         * If strict DNSSEC mode is used we won't downgrade below DO level however, as packet loss
                         * might have many reasons, a broken DNSSEC implementation being only one reason. And if the
                         * user is strict on DNSSEC, then let's assume that DNSSEC is not the fault here. */

                        log_debug("Lost too many UDP packets, downgrading feature level...");
                        if (s->possible_feature_level == DNS_SERVER_FEATURE_LEVEL_DO) /* skip over TLS_PLAIN */
                                s->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;
                        else
                                s->possible_feature_level--;

                } else if (s->n_failed_tcp >= DNS_SERVER_FEATURE_RETRY_ATTEMPTS &&
                           s->packet_truncated &&
                           s->possible_feature_level > DNS_SERVER_FEATURE_LEVEL_UDP &&
                           DNS_SERVER_FEATURE_LEVEL_IS_UDP(s->possible_feature_level) &&
                           (!DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(s->possible_feature_level) || dns_server_get_dnssec_mode(s) != DNSSEC_YES)) {

                         /* We got too many TCP connection failures in a row, we had at least one truncated
                          * packet, and are on feature level above UDP. By downgrading things and getting rid
                          * of DNSSEC or EDNS0 data we hope to make the packet smaller, so that it still
                          * works via UDP given that TCP appears not to be a fallback. Note that if we are
                          * already at the lowest UDP level, we don't go further down, since that's TCP, and
                          * TCP failed too often after all. */

                        log_debug("Got too many failed TCP connection failures and truncated UDP packets, downgrading feature level...");

                        if (DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(s->possible_feature_level))
                                s->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0; /* Go DNSSEC → EDNS0 */
                        else
                                s->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_UDP; /* Go EDNS0 → UDP */
                }

                if (p != s->possible_feature_level) {

                        /* We changed the feature level, reset the counting */
                        dns_server_reset_counters(s);

                        log_full(log_level, "Using degraded feature set %s instead of %s for DNS server %s.",
                                 dns_server_feature_level_to_string(s->possible_feature_level),
                                 dns_server_feature_level_to_string(p), strna(dns_server_string_full(s)));
                }
        }

        return s->possible_feature_level;
}

int dns_server_adjust_opt(DnsServer *server, DnsPacket *packet, DnsServerFeatureLevel level) {
        size_t packet_size, udp_size;
        bool edns_do;
        int r;

        assert(server);
        assert(packet);
        assert(packet->protocol == DNS_PROTOCOL_DNS);

        /* Fix the OPT field in the packet to match our current feature level. */

        r = dns_packet_truncate_opt(packet);
        if (r < 0)
                return r;

        if (level < DNS_SERVER_FEATURE_LEVEL_EDNS0)
                return 0;

        edns_do = level >= DNS_SERVER_FEATURE_LEVEL_DO;

        udp_size = udp_header_size(server->family);

        if (in_addr_is_localhost(server->family, &server->address) > 0)
                packet_size = 65536 - udp_size; /* force linux loopback MTU if localhost address */
        else {
                /* Use the MTU pointing to the server, subtract the IP/UDP header size */
                packet_size = LESS_BY(dns_server_get_mtu(server), udp_size);

                /* On the Internet we want to avoid fragmentation for security reasons. If we saw
                 * fragmented packets, the above was too large, let's clamp it to the largest
                 * fragment we saw */
                if (server->packet_fragmented)
                        packet_size = MIN(server->received_udp_fragment_max, packet_size);

                /* Let's not pick ridiculously large sizes, i.e. not more than 4K. No one appears
                 * to ever use such large sized on the Internet IRL, hence let's not either. */
                packet_size = MIN(packet_size, 4096U);
        }

        /* Strictly speaking we quite possibly can receive larger datagrams than the MTU (since the
         * MTU is for egress, not for ingress), but more often than not the value is symmetric, and
         * we want something that does the right thing in the majority of cases, and not just in the
         * theoretical edge case. */

        /* Safety clamp, never advertise less than 512 or more than 65535 */
        packet_size = CLAMP(packet_size,
                            DNS_PACKET_UNICAST_SIZE_MAX,
                            DNS_PACKET_SIZE_MAX);

        log_debug("Announcing packet size %zu in egress EDNS(0) packet.", packet_size);

        return dns_packet_append_opt(packet, packet_size, edns_do, /* include_rfc6975 = */ true, NULL, 0, NULL);
}

int dns_server_ifindex(const DnsServer *s) {
        assert(s);

        /* The link ifindex always takes precedence */
        if (s->link)
                return s->link->ifindex;

        if (s->ifindex > 0)
                return s->ifindex;

        return 0;
}

uint16_t dns_server_port(const DnsServer *s) {
        assert(s);

        if (s->port > 0)
                return s->port;

        return 53;
}

const char *dns_server_string(DnsServer *server) {
        assert(server);

        if (!server->server_string)
                (void) in_addr_ifindex_to_string(server->family, &server->address, dns_server_ifindex(server), &server->server_string);

        return server->server_string;
}

const char *dns_server_string_full(DnsServer *server) {
        assert(server);

        if (!server->server_string_full)
                (void) in_addr_port_ifindex_name_to_string(
                                server->family,
                                &server->address,
                                server->port,
                                dns_server_ifindex(server),
                                server->server_name,
                                &server->server_string_full);

        return server->server_string_full;
}

bool dns_server_dnssec_supported(DnsServer *server) {
        assert(server);

        /* Returns whether the server supports DNSSEC according to what we know about it */

        if (dns_server_get_dnssec_mode(server) == DNSSEC_YES) /* If strict DNSSEC mode is enabled, always assume DNSSEC mode is supported. */
                return true;

        if (!DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(server->possible_feature_level))
                return false;

        if (server->packet_bad_opt)
                return false;

        if (server->packet_rrsig_missing)
                return false;

        if (server->packet_do_off)
                return false;

        /* DNSSEC servers need to support TCP properly (see RFC5966), if they don't, we assume DNSSEC is borked too */
        if (server->n_failed_tcp >= DNS_SERVER_FEATURE_RETRY_ATTEMPTS)
                return false;

        return true;
}

void dns_server_warn_downgrade(DnsServer *server) {
        assert(server);

        if (server->warned_downgrade)
                return;

        log_struct(LOG_NOTICE,
                   "MESSAGE_ID=" SD_MESSAGE_DNSSEC_DOWNGRADE_STR,
                   LOG_MESSAGE("Server %s does not support DNSSEC, downgrading to non-DNSSEC mode.",
                               strna(dns_server_string_full(server))),
                   "DNS_SERVER=%s", strna(dns_server_string_full(server)),
                   "DNS_SERVER_FEATURE_LEVEL=%s", dns_server_feature_level_to_string(server->possible_feature_level));

        server->warned_downgrade = true;
}

size_t dns_server_get_mtu(DnsServer *s) {
        assert(s);

        if (s->link && s->link->mtu != 0)
                return s->link->mtu;

        return manager_find_mtu(s->manager);
}

static void dns_server_hash_func(const DnsServer *s, struct siphash *state) {
        assert(s);

        siphash24_compress(&s->family, sizeof(s->family), state);
        siphash24_compress(&s->address, FAMILY_ADDRESS_SIZE(s->family), state);
        siphash24_compress(&s->port, sizeof(s->port), state);
        siphash24_compress(&s->ifindex, sizeof(s->ifindex), state);
        siphash24_compress_string(s->server_name, state);
}

static int dns_server_compare_func(const DnsServer *x, const DnsServer *y) {
        int r;

        r = CMP(x->family, y->family);
        if (r != 0)
                return r;

        r = memcmp(&x->address, &y->address, FAMILY_ADDRESS_SIZE(x->family));
        if (r != 0)
                return r;

        r = CMP(x->port, y->port);
        if (r != 0)
                return r;

        r = CMP(x->ifindex, y->ifindex);
        if (r != 0)
                return r;

        return streq_ptr(x->server_name, y->server_name);
}

DEFINE_HASH_OPS(dns_server_hash_ops, DnsServer, dns_server_hash_func, dns_server_compare_func);

void dns_server_unlink_all(DnsServer *first) {
        DnsServer *next;

        if (!first)
                return;

        next = first->servers_next;
        dns_server_unlink(first);

        dns_server_unlink_all(next);
}

bool dns_server_unlink_marked(DnsServer *server) {
        bool changed = false;

        while (server) {
                DnsServer *next;

                next = server->servers_next;

                if (server->marked) {
                        dns_server_unlink(server);
                        changed = true;
                }

                server = next;
        }

        return changed;
}

void dns_server_mark_all(DnsServer *server) {
        while (server) {
                server->marked = true;
                server = server->servers_next;
        }
}

DnsServer *dns_server_find(DnsServer *first, int family, const union in_addr_union *in_addr, uint16_t port, int ifindex, const char *name) {
        LIST_FOREACH(servers, s, first)
                if (s->family == family &&
                    in_addr_equal(family, &s->address, in_addr) > 0 &&
                    s->port == port &&
                    s->ifindex == ifindex &&
                    streq_ptr(s->server_name, name))
                        return s;

        return NULL;
}

DnsServer *manager_get_first_dns_server(Manager *m, DnsServerType t) {
        assert(m);

        switch (t) {

        case DNS_SERVER_SYSTEM:
                return m->dns_servers;

        case DNS_SERVER_FALLBACK:
                return m->fallback_dns_servers;

        default:
                return NULL;
        }
}

DnsServer *manager_set_dns_server(Manager *m, DnsServer *s) {
        assert(m);

        if (m->current_dns_server == s)
                return s;

        /* Let's log about the server switch, at debug level. Except if we switch from a non-fallback server
         * to a fallback server or back, since that is noteworthy and possibly a configuration issue */
        if (s)
                log_full((s->type == DNS_SERVER_FALLBACK) != (m->current_dns_server && m->current_dns_server->type == DNS_SERVER_FALLBACK) ? LOG_NOTICE : LOG_DEBUG,
                         "Switching to %s DNS server %s.", dns_server_type_to_string(s->type), strna(dns_server_string_full(s)));

        dns_server_unref(m->current_dns_server);
        m->current_dns_server = dns_server_ref(s);

        if (m->unicast_scope)
                dns_cache_flush(&m->unicast_scope->cache);

        (void) manager_send_changed(m, "CurrentDNSServer");

        return s;
}

DnsServer *manager_get_dns_server(Manager *m) {
        Link *l;
        assert(m);

        /* Try to read updates resolv.conf */
        manager_read_resolv_conf(m);

        /* If no DNS server was chosen so far, pick the first one */
        if (!m->current_dns_server ||
            /* In case m->current_dns_server != m->dns_servers */
            manager_server_is_stub(m, m->current_dns_server))
                manager_set_dns_server(m, m->dns_servers);

        while (m->current_dns_server &&
               manager_server_is_stub(m, m->current_dns_server)) {
                manager_next_dns_server(m, NULL);
                if (m->current_dns_server == m->dns_servers)
                        manager_set_dns_server(m, NULL);
        }

        if (!m->current_dns_server) {
                bool found = false;

                /* No DNS servers configured, let's see if there are
                 * any on any links. If not, we use the fallback
                 * servers */

                HASHMAP_FOREACH(l, m->links)
                        if (l->dns_servers) {
                                found = true;
                                break;
                        }

                if (!found)
                        manager_set_dns_server(m, m->fallback_dns_servers);
        }

        return m->current_dns_server;
}

void manager_next_dns_server(Manager *m, DnsServer *if_current) {
        assert(m);

        /* If the DNS server is already a different one than the one specified in 'if_current' don't do anything */
        if (if_current && m->current_dns_server != if_current)
                return;

        /* If there's currently no DNS server set, then the next manager_get_dns_server() will find one */
        if (!m->current_dns_server)
                return;

        /* Change to the next one, but make sure to follow the linked list only if the server is still
         * linked. */
        if (m->current_dns_server->linked && m->current_dns_server->servers_next) {
                manager_set_dns_server(m, m->current_dns_server->servers_next);
                return;
        }

        /* If there was no next one, then start from the beginning of the list */
        if (m->current_dns_server->type == DNS_SERVER_FALLBACK)
                manager_set_dns_server(m, m->fallback_dns_servers);
        else
                manager_set_dns_server(m, m->dns_servers);
}

DnssecMode dns_server_get_dnssec_mode(DnsServer *s) {
        assert(s);

        if (s->link)
                return link_get_dnssec_mode(s->link);

        return manager_get_dnssec_mode(s->manager);
}

DnsOverTlsMode dns_server_get_dns_over_tls_mode(DnsServer *s) {
        assert(s);

        if (s->link)
                return link_get_dns_over_tls_mode(s->link);

        return manager_get_dns_over_tls_mode(s->manager);
}

void dns_server_flush_cache(DnsServer *s) {
        DnsServer *current;
        DnsScope *scope;

        assert(s);

        /* Flush the cache of the scope this server belongs to */

        current = s->link ? s->link->current_dns_server : s->manager->current_dns_server;
        if (current != s)
                return;

        scope = s->link ? s->link->unicast_scope : s->manager->unicast_scope;
        if (!scope)
                return;

        dns_cache_flush(&scope->cache);
}

void dns_server_reset_features(DnsServer *s) {
        assert(s);

        s->verified_feature_level = _DNS_SERVER_FEATURE_LEVEL_INVALID;
        s->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_BEST;

        s->received_udp_fragment_max = DNS_PACKET_UNICAST_SIZE_MAX;

        s->packet_bad_opt = false;
        s->packet_rrsig_missing = false;
        s->packet_do_off = false;

        s->features_grace_period_usec = DNS_SERVER_FEATURE_GRACE_PERIOD_MIN_USEC;

        s->warned_downgrade = false;

        dns_server_reset_counters(s);

        /* Let's close the default stream, so that we reprobe with the new features */
        dns_server_unref_stream(s);
}

void dns_server_reset_features_all(DnsServer *s) {
        LIST_FOREACH(servers, i, s)
                dns_server_reset_features(i);
}

void dns_server_dump(DnsServer *s, FILE *f) {
        assert(s);

        if (!f)
                f = stdout;

        fputs("[Server ", f);
        fputs(strna(dns_server_string_full(s)), f);
        fputs(" type=", f);
        fputs(dns_server_type_to_string(s->type), f);

        if (s->type == DNS_SERVER_LINK) {
                assert(s->link);

                fputs(" interface=", f);
                fputs(s->link->ifname, f);
        }

        fputs("]\n", f);

        fputs("\tVerified feature level: ", f);
        fputs(strna(dns_server_feature_level_to_string(s->verified_feature_level)), f);
        fputc('\n', f);

        fputs("\tPossible feature level: ", f);
        fputs(strna(dns_server_feature_level_to_string(s->possible_feature_level)), f);
        fputc('\n', f);

        fputs("\tDNSSEC Mode: ", f);
        fputs(strna(dnssec_mode_to_string(dns_server_get_dnssec_mode(s))), f);
        fputc('\n', f);

        fputs("\tCan do DNSSEC: ", f);
        fputs(yes_no(dns_server_dnssec_supported(s)), f);
        fputc('\n', f);

        fprintf(f,
                "\tMaximum UDP fragment size received: %zu\n"
                "\tFailed UDP attempts: %u\n"
                "\tFailed TCP attempts: %u\n"
                "\tSeen truncated packet: %s\n"
                "\tSeen OPT RR getting lost: %s\n"
                "\tSeen RRSIG RR missing: %s\n"
                "\tSeen invalid packet: %s\n"
                "\tServer dropped DO flag: %s\n",
                s->received_udp_fragment_max,
                s->n_failed_udp,
                s->n_failed_tcp,
                yes_no(s->packet_truncated),
                yes_no(s->packet_bad_opt),
                yes_no(s->packet_rrsig_missing),
                yes_no(s->packet_invalid),
                yes_no(s->packet_do_off));
}

void dns_server_unref_stream(DnsServer *s) {
        DnsStream *ref;

        assert(s);

        /* Detaches the default stream of this server. Some special care needs to be taken here, as that stream and
         * this server reference each other. First, take the stream out of the server. It's destructor will check if it
         * is registered with us, hence let's invalidate this separately, so that it is already unregistered. */
        ref = TAKE_PTR(s->stream);

        /* And then, unref it */
        dns_stream_unref(ref);
}

DnsScope *dns_server_scope(DnsServer *s) {
        assert(s);
        assert((s->type == DNS_SERVER_LINK) == !!s->link);

        if (s->link)
                return s->link->unicast_scope;

        return s->manager->unicast_scope;
}

static const char* const dns_server_type_table[_DNS_SERVER_TYPE_MAX] = {
        [DNS_SERVER_SYSTEM]   = "system",
        [DNS_SERVER_FALLBACK] = "fallback",
        [DNS_SERVER_LINK]     = "link",
};
DEFINE_STRING_TABLE_LOOKUP(dns_server_type, DnsServerType);

static const char* const dns_server_feature_level_table[_DNS_SERVER_FEATURE_LEVEL_MAX] = {
        [DNS_SERVER_FEATURE_LEVEL_TCP]       = "TCP",
        [DNS_SERVER_FEATURE_LEVEL_UDP]       = "UDP",
        [DNS_SERVER_FEATURE_LEVEL_EDNS0]     = "UDP+EDNS0",
        [DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN] = "TLS+EDNS0",
        [DNS_SERVER_FEATURE_LEVEL_DO]        = "UDP+EDNS0+DO",
        [DNS_SERVER_FEATURE_LEVEL_TLS_DO]    = "TLS+EDNS0+DO",
};
DEFINE_STRING_TABLE_LOOKUP(dns_server_feature_level, DnsServerFeatureLevel);
