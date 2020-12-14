/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

#define NTS_NONCE_SIZE                 16
#define NTP_EXTENSION_AUTH_HEADER_SIZE 4
#define NTS_UID_SIZE                   32

typedef enum NTPExtensionFieldNTSType {
        NTP_EXTENSION_FIELD_NTS_UNIQUE_IDENTIFIER  = 0x104,
        NTP_EXTENSION_FIELD_NTS_COOKIE             = 0x204,
        NTP_EXTENSION_FIELD_NTS_COOKIE_PLACEHOLDER = 0x304,
        NTP_EXTENSION_FIELD_NTS_AEEF               = 0x404,
} NTPExtensionFieldNTSType;

/* rfc5905 7.5. NTP Extension Field Format */
typedef struct NTPExtensionField{
        uint16_t type;
        uint16_t size;
} NTPExtensionField;

typedef struct NTPExtensionPacket {
        size_t size;
        size_t offset;

        uint8_t *data;
} NTPExtensionPacket;

int ntp_extension_packet_new(size_t max_size, uint8_t *data, NTPExtensionPacket **ret);
NTPExtensionPacket *ntp_extension_packet_free(NTPExtensionPacket *p);
void ntp_extension_packet_drop_payload(NTPExtensionPacket *p);

#define ntp_extension_packet_rewind(p) (p->offset = 0)

DEFINE_TRIVIAL_CLEANUP_FUNC(NTPExtensionPacket*, ntp_extension_packet_free);

int ntp_extension_append_field(NTPExtensionPacket *message, uint16_t type, const void *data, size_t data_length);
int ntp_extension_append_field_uint16(NTPExtensionPacket *packet, uint16_t type, uint16_t data);
int ntp_extension_append_empty_field(NTPExtensionPacket *packet, uint16_t type, size_t data_size, void **data);
int ntp_extension_append_field_uint16_data(NTPExtensionPacket *packet, uint16_t data);
int ntp_extension_append_field_data(NTPExtensionPacket *packet, uint8_t *data, size_t size);

int ntp_extension_parse_packet(NTPExtensionPacket *packet);

int ntp_extension_read_field(NTPExtensionPacket *packet, uint16_t *type, size_t *total_size, void **data, size_t *data_size);
int ntp_extension_read_cookie_from_auth_field(uint8_t *message, size_t size, void **cookie, size_t *cookie_size);
