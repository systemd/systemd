/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "ordered-set.h"
#include "socket-util.h"

typedef struct DnsServer DnsServer;
typedef struct DnsStream DnsStream;
typedef struct DnsTransaction DnsTransaction;
typedef struct Manager Manager;
typedef struct DnsStubListenerExtra DnsStubListenerExtra;

#include "resolved-dns-packet.h"
#include "resolved-dnstls.h"

/* Various timeouts for establishing TCP connections. First the default timeout for that. */
#define DNS_STREAM_DEFAULT_TIMEOUT_USEC (10 * USEC_PER_SEC)

/* In the DNS stub, be more friendly for incoming connections, than we are to ourselves for outgoing ones */
#define DNS_STREAM_STUB_TIMEOUT_USEC (30 * USEC_PER_SEC)

/* In opportunistic TLS mode, lower timeouts */
#define DNS_STREAM_OPPORTUNISTIC_TLS_TIMEOUT_USEC (3 * USEC_PER_SEC)

/* Once connections are established apply this timeout once nothing happens anymore */
#define DNS_STREAM_ESTABLISHED_TIMEOUT_USEC (10 * USEC_PER_SEC)

typedef enum DnsStreamType {
        DNS_STREAM_LOOKUP,        /* Outgoing connection to a classic DNS server */
        DNS_STREAM_LLMNR_SEND,    /* Outgoing LLMNR TCP lookup */
        DNS_STREAM_LLMNR_RECV,    /* Incoming LLMNR TCP lookup */
        DNS_STREAM_STUB,          /* Incoming DNS stub connection */
        _DNS_STREAM_TYPE_MAX,
        _DNS_STREAM_TYPE_INVALID = -EINVAL,
} DnsStreamType;

#define DNS_STREAM_WRITE_TLS_DATA 1

/* Streams are used by three subsystems:
 *
 *   1. The normal transaction logic when doing a DNS or LLMNR lookup via TCP
 *   2. The LLMNR logic when accepting a TCP-based lookup
 *   3. The DNS stub logic when accepting a TCP-based lookup
 */

struct DnsStream {
        Manager *manager;
        unsigned n_ref;

        DnsStreamType type;
        DnsProtocol protocol;

        int fd;
        union sockaddr_union peer;
        socklen_t peer_salen;
        union sockaddr_union local;
        socklen_t local_salen;
        int ifindex;
        uint32_t ttl;
        bool identified;
        bool packet_received; /* At least one packet is received. Used by LLMNR. */
        uint32_t requested_events;

        /* only when using TCP fast open */
        union sockaddr_union tfo_address;
        socklen_t tfo_salen;

#if ENABLE_DNS_OVER_TLS
        DnsTlsStreamData dnstls_data;
        uint32_t dnstls_events;
#endif

        sd_event_source *io_event_source;
        sd_event_source *timeout_event_source;

        be16_t write_size, read_size;
        DnsPacket *write_packet, *read_packet;
        size_t n_written, n_read;
        OrderedSet *write_queue;

        int (*on_packet)(DnsStream *s, DnsPacket *p);
        int (*complete)(DnsStream *s, int error);

        LIST_HEAD(DnsTransaction, transactions); /* when used by the transaction logic */
        DnsServer *server;                       /* when used by the transaction logic */
        Set *queries;                            /* when used by the DNS stub logic */

        /* used when DNS-over-TLS is enabled */
        bool encrypted:1;

        DnsStubListenerExtra *stub_listener_extra;

        LIST_FIELDS(DnsStream, streams);
};

int dns_stream_new(
                Manager *m,
                DnsStream **ret,
                DnsStreamType type,
                DnsProtocol protocol,
                int fd,
                const union sockaddr_union *tfo_address,
                int (on_packet)(DnsStream*, DnsPacket*),
                int (complete)(DnsStream*, int), /* optional */
                usec_t connect_timeout_usec);
#if ENABLE_DNS_OVER_TLS
int dns_stream_connect_tls(DnsStream *s, void *tls_session);
#endif
DnsStream *dns_stream_unref(DnsStream *s);
DnsStream *dns_stream_ref(DnsStream *s);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsStream*, dns_stream_unref);

int dns_stream_write_packet(DnsStream *s, DnsPacket *p);
ssize_t dns_stream_writev(DnsStream *s, const struct iovec *iov, size_t iovcnt, int flags);

static inline bool DNS_STREAM_QUEUED(DnsStream *s) {
        assert(s);

        if (s->fd < 0) /* already stopped? */
                return false;

        return !!s->write_packet;
}

void dns_stream_detach(DnsStream *s);
int dns_stream_disconnect_all(Manager *m);
