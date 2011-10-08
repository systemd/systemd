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
typedef struct EntryObject EntryObject;
typedef struct HashTableObject HashTableObject;
typedef struct BisectTableObject BisectTableObject;
typedef struct EntryItem EntryItem;
typedef struct HashItem HashItem;

/* Object types */
enum {
        OBJECT_UNUSED,
        OBJECT_DATA,
        OBJECT_ENTRY,
        OBJECT_HASH_TABLE,
        OBJECT_BISECT_TABLE
};

_packed_ struct ObjectHeader {
        uint8_t type;
        uint8_t reserved[7];
        uint64_t size;
        uint8_t payload[];
};

_packed_ struct DataObject {
        ObjectHeader object;
        uint64_t hash;
        uint64_t head_entry_offset;
        uint64_t tail_entry_offset;
        uint64_t prev_hash_offset;
        uint64_t next_hash_offset;
        uint8_t payload[];
};

_packed_ struct EntryItem {
        uint64_t object_offset;
        uint64_t prev_entry_offset;
        uint64_t next_entry_offset;
};

_packed_ struct EntryObject {
        ObjectHeader object;
        uint64_t seqnum;
        uint64_t realtime;
        uint64_t monotonic;
        sd_id128_t boot_id;
        uint64_t xor_hash;
        uint64_t prev_entry_offset;
        uint64_t next_entry_offset;
        EntryItem items[];
};

_packed_ struct HashItem {
        uint64_t head_hash_offset;
        uint64_t tail_hash_offset;
};

_packed_ struct HashTableObject {
        ObjectHeader object;
        HashItem table[];
};

_packed_ struct BisectTableObject {
        ObjectHeader object;
        uint64_t table[];
};

union Object {
        ObjectHeader object;
        DataObject data;
        EntryObject entry;
        HashTableObject hash_table;
        BisectTableObject bisect_table;
};

enum {
        STATE_OFFLINE,
        STATE_ONLINE,
        STATE_ARCHIVED
};

_packed_ struct Header {
        uint8_t signature[8]; /* "LPKSHHRH" */
        uint32_t compatible_flags;
        uint32_t incompatible_flags;
        uint32_t state;
        uint8_t reserved[4];
        sd_id128_t file_id;
        sd_id128_t machine_id;
        sd_id128_t boot_id;
        sd_id128_t seqnum_id;
        uint64_t arena_offset;
        uint64_t arena_size;
        uint64_t arena_max_size;
        uint64_t arena_min_size;
        uint64_t arena_keep_free;
        uint64_t hash_table_offset;     /* for looking up data objects */
        uint64_t hash_table_size;
        uint64_t bisect_table_offset;   /* for looking up entry objects */
        uint64_t bisect_table_size;
        uint64_t head_object_offset;
        uint64_t tail_object_offset;
        uint64_t head_entry_offset;
        uint64_t tail_entry_offset;
        uint64_t last_bisect_offset;
        uint64_t n_objects;
        uint64_t seqnum;
};

#endif
