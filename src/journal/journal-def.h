/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include "sparse-endian.h"

#include "systemd/sd-id128.h"

#include "macro.h"

/*
 * If you change this file you probably should also change its documentation:
 *
 * http://www.freedesktop.org/wiki/Software/systemd/journal-files
 *
 */

typedef struct Header Header;

typedef struct ObjectHeader ObjectHeader;
typedef union Object Object;

typedef struct DataObject DataObject;
typedef struct FieldObject FieldObject;
typedef struct EntryObject EntryObject;
typedef struct HashTableObject HashTableObject;
typedef struct EntryArrayObject EntryArrayObject;
typedef struct TagObject TagObject;

typedef struct EntryItem EntryItem;
typedef struct HashItem HashItem;

typedef struct FSSHeader FSSHeader;

/* Object types */
typedef enum ObjectType {
        OBJECT_UNUSED, /* also serves as "any type" or "additional context" */
        OBJECT_DATA,
        OBJECT_FIELD,
        OBJECT_ENTRY,
        OBJECT_DATA_HASH_TABLE,
        OBJECT_FIELD_HASH_TABLE,
        OBJECT_ENTRY_ARRAY,
        OBJECT_TAG,
        _OBJECT_TYPE_MAX
} ObjectType;

/* Object flags */
enum {
        OBJECT_COMPRESSED_XZ = 1 << 0,
        OBJECT_COMPRESSED_LZ4 = 1 << 1,
        _OBJECT_COMPRESSED_MAX
};

#define OBJECT_COMPRESSION_MASK (OBJECT_COMPRESSED_XZ | OBJECT_COMPRESSED_LZ4)

struct ObjectHeader {
        uint8_t type;
        uint8_t flags;
        uint8_t reserved[6];
        le64_t size;
        uint8_t payload[];
} _packed_;

struct DataObject {
        ObjectHeader object;
        le64_t hash;
        le64_t next_hash_offset;
        le64_t next_field_offset;
        le64_t entry_offset; /* the first array entry we store inline */
        le64_t entry_array_offset;
        le64_t n_entries;
        uint8_t payload[];
} _packed_;

struct FieldObject {
        ObjectHeader object;
        le64_t hash;
        le64_t next_hash_offset;
        le64_t head_data_offset;
        uint8_t payload[];
} _packed_;

struct EntryItem {
        le64_t object_offset;
        le64_t hash;
} _packed_;

struct EntryObject {
        ObjectHeader object;
        le64_t seqnum;
        le64_t realtime;
        le64_t monotonic;
        sd_id128_t boot_id;
        le64_t xor_hash;
        EntryItem items[];
} _packed_;

struct HashItem {
        le64_t head_hash_offset;
        le64_t tail_hash_offset;
} _packed_;

struct HashTableObject {
        ObjectHeader object;
        HashItem items[];
} _packed_;

struct EntryArrayObject {
        ObjectHeader object;
        le64_t next_entry_array_offset;
        le64_t items[];
} _packed_;

#define TAG_LENGTH (256/8)

struct TagObject {
        ObjectHeader object;
        le64_t seqnum;
        le64_t epoch;
        uint8_t tag[TAG_LENGTH]; /* SHA-256 HMAC */
} _packed_;

union Object {
        ObjectHeader object;
        DataObject data;
        FieldObject field;
        EntryObject entry;
        HashTableObject hash_table;
        EntryArrayObject entry_array;
        TagObject tag;
};

enum {
        STATE_OFFLINE = 0,
        STATE_ONLINE = 1,
        STATE_ARCHIVED = 2,
        _STATE_MAX
};

/* Header flags */
enum {
        HEADER_INCOMPATIBLE_COMPRESSED_XZ = 1 << 0,
        HEADER_INCOMPATIBLE_COMPRESSED_LZ4 = 1 << 1,
};

#define HEADER_INCOMPATIBLE_ANY (HEADER_INCOMPATIBLE_COMPRESSED_XZ|HEADER_INCOMPATIBLE_COMPRESSED_LZ4)

#if defined(HAVE_XZ) && defined(HAVE_LZ4)
#  define HEADER_INCOMPATIBLE_SUPPORTED HEADER_INCOMPATIBLE_ANY
#elif defined(HAVE_XZ)
#  define HEADER_INCOMPATIBLE_SUPPORTED HEADER_INCOMPATIBLE_COMPRESSED_XZ
#elif defined(HAVE_LZ4)
#  define HEADER_INCOMPATIBLE_SUPPORTED HEADER_INCOMPATIBLE_COMPRESSED_LZ4
#else
#  define HEADER_INCOMPATIBLE_SUPPORTED 0
#endif

enum {
        HEADER_COMPATIBLE_SEALED = 1
};

#define HEADER_COMPATIBLE_ANY HEADER_COMPATIBLE_SEALED
#ifdef HAVE_GCRYPT
#  define HEADER_COMPATIBLE_SUPPORTED HEADER_COMPATIBLE_SEALED
#else
#  define HEADER_COMPATIBLE_SUPPORTED 0
#endif

#define HEADER_SIGNATURE ((char[]) { 'L', 'P', 'K', 'S', 'H', 'H', 'R', 'H' })

struct Header {
        uint8_t signature[8]; /* "LPKSHHRH" */
        le32_t compatible_flags;
        le32_t incompatible_flags;
        uint8_t state;
        uint8_t reserved[7];
        sd_id128_t file_id;
        sd_id128_t machine_id;
        sd_id128_t boot_id;    /* last writer */
        sd_id128_t seqnum_id;
        le64_t header_size;
        le64_t arena_size;
        le64_t data_hash_table_offset;
        le64_t data_hash_table_size;
        le64_t field_hash_table_offset;
        le64_t field_hash_table_size;
        le64_t tail_object_offset;
        le64_t n_objects;
        le64_t n_entries;
        le64_t tail_entry_seqnum;
        le64_t head_entry_seqnum;
        le64_t entry_array_offset;
        le64_t head_entry_realtime;
        le64_t tail_entry_realtime;
        le64_t tail_entry_monotonic;
        /* Added in 187 */
        le64_t n_data;
        le64_t n_fields;
        /* Added in 189 */
        le64_t n_tags;
        le64_t n_entry_arrays;

        /* Size: 240 */
} _packed_;

#define FSS_HEADER_SIGNATURE ((char[]) { 'K', 'S', 'H', 'H', 'R', 'H', 'L', 'P' })

struct FSSHeader {
        uint8_t signature[8]; /* "KSHHRHLP" */
        le32_t compatible_flags;
        le32_t incompatible_flags;
        sd_id128_t machine_id;
        sd_id128_t boot_id;    /* last writer */
        le64_t header_size;
        le64_t start_usec;
        le64_t interval_usec;
        le16_t fsprg_secpar;
        le16_t reserved[3];
        le64_t fsprg_state_size;
} _packed_;
