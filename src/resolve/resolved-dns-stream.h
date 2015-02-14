/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "socket-util.h"

typedef struct DnsStream DnsStream;

#include "resolved-dns-packet.h"
#include "resolved-dns-transaction.h"

struct DnsStream {
        Manager *manager;

        DnsProtocol protocol;

        int fd;
        union sockaddr_union peer;
        socklen_t peer_salen;
        union sockaddr_union local;
        socklen_t local_salen;
        int ifindex;
        uint32_t ttl;
        bool identified;

        sd_event_source *io_event_source;
        sd_event_source *timeout_event_source;

        be16_t write_size, read_size;
        DnsPacket *write_packet, *read_packet;
        size_t n_written, n_read;

        int (*on_packet)(DnsStream *s);
        int (*complete)(DnsStream *s, int error);

        DnsTransaction *transaction;

        LIST_FIELDS(DnsStream, streams);
};

int dns_stream_new(Manager *m, DnsStream **s, DnsProtocol protocol, int fd);
DnsStream *dns_stream_free(DnsStream *s);

int dns_stream_write_packet(DnsStream *s, DnsPacket *p);
