#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include "resolved-dns-answer.h"
#include "resolved-dns-question.h"
#include "resolved-manager.h"

int dns_synthesize_ifindex(int ifindex);
int dns_synthesize_family(uint64_t flags);
DnsProtocol dns_synthesize_protocol(uint64_t flags);

int dns_synthesize_answer(Manager *m, DnsQuestion *q, int ifindex, DnsAnswer **ret);
