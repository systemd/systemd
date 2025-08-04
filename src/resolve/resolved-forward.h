/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"    /* IWYU pragma: export */
#include "forward.h"                /* IWYU pragma: export */

typedef enum DnsAnswerFlags DnsAnswerFlags;
typedef enum DnsCacheMode DnsCacheMode;
typedef enum DnsProtocol DnsProtocol;
typedef enum DnssecResult DnssecResult;
typedef enum DnssecVerdict DnssecVerdict;
typedef enum DnsScopeOrigin DnsScopeOrigin;
typedef enum DnsTransactionState DnsTransactionState;
typedef enum ResolveConfigSource ResolveConfigSource;

typedef struct DnsAnswer DnsAnswer;
typedef struct DnsDelegate DnsDelegate;
typedef struct DnsPacket DnsPacket;
typedef struct DnsQuery DnsQuery;
typedef struct DnsQueryCandidate DnsQueryCandidate;
typedef struct DnsQuestion DnsQuestion;
typedef struct DnsResourceKey DnsResourceKey;
typedef struct DnsResourceRecord DnsResourceRecord;
typedef struct DnsScope DnsScope;
typedef struct DnssdService DnssdService;
typedef struct DnssdTxtData DnssdTxtData;
typedef struct DnsSearchDomain DnsSearchDomain;
typedef struct DnsServer DnsServer;
typedef struct DnsStream DnsStream;
typedef struct DnsStubListenerExtra DnsStubListenerExtra;
typedef struct DnsSvcParam DnsSvcParam;
typedef struct DnsTransaction DnsTransaction;
typedef struct DnsTxtItem DnsTxtItem;
typedef struct DnsZoneItem DnsZoneItem;
typedef struct Link Link;
typedef struct LinkAddress LinkAddress;
typedef struct Manager Manager;
typedef struct SocketGraveyard SocketGraveyard;
