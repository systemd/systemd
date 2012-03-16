/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foojournaldefhfoo
#define foojournaldefhfoo

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sparse-endian.h"

#include <systemd/sd-id128.h>

#include "macro.h"

typedef struct Header Header;
typedef struct ObjectHeader ObjectHeader;
typedef union Object Object;
typedef struct DataObject DataObject;
typedef struct FieldObject FieldObject;
typedef struct EntryObject EntryObject;
typedef struct HashTableObject HashTableObject;
typedef struct EntryArrayObject EntryArrayObject;
typedef struct EntryItem EntryItem;
typedef struct HashItem HashItem;

/* Object types */
enum {
        OBJECT_UNUSED,
        OBJECT_DATA,
        OBJECT_FIELD,
        OBJECT_ENTRY,
        OBJECT_DATA_HASH_TABLE,
        OBJECT_FIELD_HASH_TABLE,
        OBJECT_ENTRY_ARRAY,
        _OBJECT_TYPE_MAX
};

/* Object flags */
enum {
        OBJECT_COMPRESSED = 1
};

_packed_ struct ObjectHeader {
        uint8_t type;
        uint8_t flags;
        uint8_t reserved[6];
        le64_t size;
        uint8_t payload[];
};

_packed_ struct DataObject {
        ObjectHeader object;
        le64_t hash;
        le64_t next_hash_offset;
        le64_t next_field_offset;
        le64_t entry_offset; /* the first array entry we store inline */
        le64_t entry_array_offset;
        le64_t n_entries;
        uint8_t payload[];
};

_packed_ struct FieldObject {
        ObjectHeader object;
        le64_t hash;
        le64_t next_hash_offset;
        le64_t head_data_offset;
        le64_t tail_data_offset;
        uint8_t payload[];
};

_packed_ struct EntryItem {
        le64_t object_offset;
        le64_t hash;
};

_packed_ struct EntryObject {
        ObjectHeader object;
        le64_t seqnum;
        le64_t realtime;
        le64_t monotonic;
        sd_id128_t boot_id;
        le64_t xor_hash;
        EntryItem items[];
};

_packed_ struct HashItem {
        le64_t head_hash_offset;
        le64_t tail_hash_offset;
};

_packed_ struct HashTableObject {
        ObjectHeader object;
        HashItem items[];
};

_packed_ struct EntryArrayObject {
        ObjectHeader object;
        le64_t next_entry_array_offset;
        le64_t items[];
};

union Object {
        ObjectHeader object;
        DataObject data;
        FieldObject field;
        EntryObject entry;
        HashTableObject hash_table;
        EntryArrayObject entry_array;
};

enum {
        STATE_OFFLINE,
        STATE_ONLINE,
        STATE_ARCHIVED
};

/* Header flags */
enum {
        HEADER_INCOMPATIBLE_COMPRESSED = 1
};

_packed_ struct Header {
        uint8_t signature[8]; /* "LPKSHHRH" */
        uint32_t compatible_flags;
        uint32_t incompatible_flags;
        uint8_t state;
        uint8_t reserved[7];
        sd_id128_t file_id;
        sd_id128_t machine_id;
        sd_id128_t boot_id;
        sd_id128_t seqnum_id;
        le64_t arena_offset;
        le64_t arena_size;
        le64_t data_hash_table_offset;     /* for looking up data objects */
        le64_t data_hash_table_size;
        le64_t field_hash_table_offset;     /* for looking up field objects */
        le64_t field_hash_table_size;
        le64_t tail_object_offset;
        le64_t n_objects;
        le64_t n_entries;
        le64_t seqnum;
        le64_t first_seqnum;
        le64_t entry_array_offset;
        le64_t head_entry_realtime;
        le64_t tail_entry_realtime;
        le64_t tail_entry_monotonic;
};

#endif
