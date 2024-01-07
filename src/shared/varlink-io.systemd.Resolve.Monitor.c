/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Resolve.Monitor.h"

VARLINK_DEFINE_STRUCT_TYPE(
                ResourceKey,
                VARLINK_DEFINE_FIELD(class, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(type, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(name, VARLINK_STRING, 0));

VARLINK_DEFINE_STRUCT_TYPE(
                ResourceRecord,
                VARLINK_DEFINE_FIELD_BY_TYPE(key, ResourceKey, 0),
                VARLINK_DEFINE_FIELD(priority, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(weight, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(port, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(name, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(cpu, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(os, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(items, VARLINK_STRING, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(address, VARLINK_INT, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(mname, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(rname, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(serial, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(refresh, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(expire, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(minimum, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(exchange, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(version, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(size, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(horiz_pre, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(vert_pre, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(latitude, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(longitude, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(altitude, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(keyTag, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(algorithm, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(digestType, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(digest, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(fptype, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(fingerprint, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(flags, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(protocol, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(dnskey, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(signer, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(typeCovered, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(labels, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(originalTtl, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(expiration, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(inception, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(signature, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(nextDomain, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(types, VARLINK_INT, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(iterations, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(salt, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(hash, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(certUsage, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(selector, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(matchingType, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(data, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(tag, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(value, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(target, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(params, VARLINK_STRING, VARLINK_NULLABLE));

VARLINK_DEFINE_STRUCT_TYPE(
                ResourceRecordArray,
                VARLINK_DEFINE_FIELD_BY_TYPE(rr, ResourceRecord, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(raw, VARLINK_STRING, 0));

VARLINK_DEFINE_STRUCT_TYPE(
                Answer,
                VARLINK_DEFINE_FIELD_BY_TYPE(rr, ResourceRecord, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(raw, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(ifindex, VARLINK_INT, VARLINK_NULLABLE));

VARLINK_DEFINE_METHOD(
                SubscribeQueryResults,
                /* First reply */
                VARLINK_DEFINE_OUTPUT(ready, VARLINK_BOOL, VARLINK_NULLABLE),
                /* Subsequent replies */
                VARLINK_DEFINE_OUTPUT(state, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(rcode, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(errno, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(question, ResourceKey, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(collectedQuestions, ResourceKey, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(answer, Answer, VARLINK_NULLABLE|VARLINK_ARRAY));

VARLINK_DEFINE_STRUCT_TYPE(
                CacheEntry,
                VARLINK_DEFINE_FIELD_BY_TYPE(key, ResourceKey, 0),
                VARLINK_DEFINE_FIELD_BY_TYPE(rrs, ResourceRecordArray, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(type, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(until, VARLINK_INT, 0));

VARLINK_DEFINE_STRUCT_TYPE(
                ScopeCache,
                VARLINK_DEFINE_FIELD(protocol, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(family, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(ifindex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(ifname, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD_BY_TYPE(cache, CacheEntry, VARLINK_ARRAY));

VARLINK_DEFINE_METHOD(
                DumpCache,
                VARLINK_DEFINE_OUTPUT_BY_TYPE(dump, ScopeCache, VARLINK_ARRAY));

VARLINK_DEFINE_STRUCT_TYPE(
                ServerState,
                VARLINK_DEFINE_FIELD(Server, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(Type, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(Interface, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(InterfaceIndex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(VerifiedFeatureLevel, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(PossibleFeatureLevel, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(DNSSECMode, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(DNSSECSupported, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(ReceivedUDPFragmentMax, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(FailedUDPAttempts, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(FailedTCPAttempts, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(PacketTruncated, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(PacketBadOpt, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(PacketRRSIGMissing, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(PacketInvalid, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(PacketDoOff, VARLINK_BOOL, 0));

VARLINK_DEFINE_METHOD(
                DumpServerState,
                VARLINK_DEFINE_OUTPUT_BY_TYPE(dump, ServerState, VARLINK_ARRAY));

VARLINK_DEFINE_STRUCT_TYPE(
                TransactionStatistics,
                VARLINK_DEFINE_FIELD(currentTransactions, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(totalTransactions, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(totalTimeouts, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(totalTimeoutsServedStale, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(totalFailedResponses, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(totalFailedResponsesServedStale, VARLINK_INT, 0));

VARLINK_DEFINE_STRUCT_TYPE(
                CacheStatistics,
                VARLINK_DEFINE_FIELD(size, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(hits, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(misses, VARLINK_INT, 0));

VARLINK_DEFINE_STRUCT_TYPE(
                DnssecStatistics,
                VARLINK_DEFINE_FIELD(secure, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(insecure, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(bogus, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(indeterminate, VARLINK_INT, 0));

VARLINK_DEFINE_METHOD(
                DumpStatistics,
                VARLINK_DEFINE_OUTPUT_BY_TYPE(transactions, TransactionStatistics, 0),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(cache, CacheStatistics, 0),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(dnssec, DnssecStatistics, 0));

VARLINK_DEFINE_METHOD(ResetStatistics);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Resolve_Monitor,
                "io.systemd.Resolve.Monitor",
                &vl_method_SubscribeQueryResults,
                &vl_method_DumpCache,
                &vl_method_DumpServerState,
                &vl_method_DumpStatistics,
                &vl_method_ResetStatistics,
                &vl_type_ResourceKey,
                &vl_type_ResourceRecord,
                &vl_type_ResourceRecordArray,
                &vl_type_Answer,
                &vl_type_CacheEntry,
                &vl_type_ScopeCache,
                &vl_type_TransactionStatistics,
                &vl_type_CacheStatistics,
                &vl_type_DnssecStatistics,
                &vl_type_ServerState);
