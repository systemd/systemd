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

#include <inttypes.h>

#include "macro.h"
#include "sd-id128.h"

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
        uint64_t size;
        uint8_t payload[];
};

_packed_ struct DataObject {
        ObjectHeader object;
        uint64_t hash;
        uint64_t next_hash_offset;
        uint64_t next_field_offset;
        uint64_t entry_offset; /* the first array entry we store inline */
        uint64_t entry_array_offset;
        uint64_t n_entries;
        uint8_t payload[];
};

_packed_ struct FieldObject {
        ObjectHeader object;
        uint64_t hash;
        uint64_t next_hash_offset;
        uint64_t head_data_offset;
        uint64_t tail_data_offset;
        uint8_t payload[];
};

_packed_ struct EntryItem {
        uint64_t object_offset;
        uint64_t hash;
};

_packed_ struct EntryObject {
        ObjectHeader object;
        uint64_t seqnum;
        uint64_t realtime;
        uint64_t monotonic;
        sd_id128_t boot_id;
        uint64_t xor_hash;
        EntryItem items[];
};

_packed_ struct HashItem {
        uint64_t head_hash_offset;
        uint64_t tail_hash_offset;
};

_packed_ struct HashTableObject {
        ObjectHeader object;
        HashItem items[];
};

_packed_ struct EntryArrayObject {
        ObjectHeader object;
        uint64_t next_entry_array_offset;
        uint64_t items[];
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
        uint64_t arena_offset;
        uint64_t arena_size;
        uint64_t data_hash_table_offset;     /* for looking up data objects */
        uint64_t data_hash_table_size;
        uint64_t field_hash_table_offset;     /* for looking up field objects */
        uint64_t field_hash_table_size;
        uint64_t tail_object_offset;
        uint64_t n_objects;
        uint64_t n_entries;
        uint64_t seqnum;
        uint64_t first_seqnum;
        uint64_t entry_array_offset;
        uint64_t head_entry_realtime;
        uint64_t tail_entry_realtime;
        uint64_t tail_entry_monotonic;
};

#endif
