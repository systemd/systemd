/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

/* rfc8915: Network Time Security for the Network Time Protocol */
#define NTS_KE_RECORD_CRITICAL_BIT   0x8000
#define NTS_KE_NEXT_PROTOCOL_NTPV4   0

#define NTS_KE_MESSAGE_SIZE_MAX      16384
#define NTS_KE_MAX_RECORD_BODY_SIZE  256
#define NTS_KE_COOKIE_SIZE_MAX       256
#define NTS_KE_COOKIES_MAX           8
#define NTS_KE_KEY_SIZE_MAX          64
#define NTS_HEADER_SIZE              4
#define NTS_UID_SIZE                 32
#define CMAC_SIZE 16

#define NTSKE_LABEL                  "EXPORTER-network-time-security"
#define NTSKE_CONTEXT_C2S            "\x0\x0\x0\xf\x0"
#define NTSKE_CONTEXT_S2C            "\x0\x0\x0\xf\x1"

/* rfc5297 Synthetic Initialization Vector (SIV) Authenticated Encryption
 *  Using the Advanced Encryption Standard (AES) SIV algorithms
 */
typedef enum AeadAesSivAlgorithm {
        AEAD_AES_SIV_CMAC_256 = 15,
        AEAD_AES_SIV_CMAC_384 = 16,
        AEAD_AES_SIV_CMAC_512 = 17,
        AEAD_NO_CIPHER        = 0xffff,
} AeadAesSivAlgorithm;

/* rfc8915 4.1. NTS-KE Record Types */
typedef enum NTSKERecordType {
        NTS_KE_RECORD_END_OF_MESSAGE,
        NTS_KE_RECORD_NEXT_PROTOCOL,
        NTS_KE_RECORD_ERROR,
        NTS_KE_RECORD_WARNING,
        NTS_KE_RECORD_AEAD_ALGORITHM,
        NTS_KE_RECORD_COOKIE,
        NTS_KE_RECORD_NTPV4_SERVER_NEGOTIATION,
        NTS_KE_RECORD_NTPV4_PORT_NEGOTIATION,
        _NTS_KE_RECORD_TYPE_MAX,
        _NTS_KE_RECORD_TYPE_INVALID = -1
} NTSKERecordType;

typedef struct NTSKERecord {
        uint16_t type;
        uint16_t size;
} NTSKERecord;

typedef struct NTSCookie {
        size_t size;
        uint8_t cookie[NTS_KE_COOKIE_SIZE_MAX];
} NTSCookie;

typedef struct NTSKEPacket {
        size_t size;
        size_t read;
        size_t offset;
        uint8_t *data;
        bool payload:1;

        /* parsed data */
        bool end:1;
        char *server;
        uint16_t port;
        uint16_t next_protocol;
        uint16_t aead_algorithm;

        NTSCookie *cookies;
        size_t n_cookies;
} NTSKEPacket;

int nts_ke_packet_new(size_t max_size, NTSKEPacket **ret);
NTSKEPacket *ntske_packet_free(NTSKEPacket *p);

void ntske_packet_drop_payload(NTSKEPacket *p);
#define ntske_packet_rewind(p) (p->offset = 0)

DEFINE_TRIVIAL_CLEANUP_FUNC(NTSKEPacket*, ntske_packet_free);

int ntske_append_record(NTSKEPacket *message, uint16_t type, const void *data, size_t data_length, bool critical);
int ntske_read_record(NTSKEPacket *message, uint16_t *type, uint8_t **data, size_t *data_length, bool *critical);

int ntske_parse_packet(NTSKEPacket *packet);
int ntske_build_request_packet(NTSKEPacket **ret);
