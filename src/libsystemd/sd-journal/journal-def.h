/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "forward.h"
#include "sparse-endian.h"

/* Make sure not to make this smaller than the maximum coredump size.
 * See JOURNAL_SIZE_MAX in coredump-config.h */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define ENTRY_SIZE_MAX (1024*1024*770u)
#define ENTRY_SIZE_UNPRIV_MAX (1024*1024*32u)
#define DATA_SIZE_MAX (1024*1024*768u)
#else
#define ENTRY_SIZE_MAX (1024*1024*13u)
#define ENTRY_SIZE_UNPRIV_MAX (1024*1024*8u)
#define DATA_SIZE_MAX (1024*1024*11u)
#endif

/* The maximum number of fields in an entry */
#define ENTRY_FIELD_COUNT_MAX 1024u

/*
 * If you change this file you probably should also change its documentation:
 *
 * https://systemd.io/JOURNAL_FILE_FORMAT
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
typedef struct SegmentedDataObject SegmentedDataObject;
typedef struct ContextObject ContextObject;
typedef struct IndexObject IndexObject;
typedef struct IndexFieldItem IndexFieldItem;
typedef struct IndexDataItem IndexDataItem;

typedef struct HashItem HashItem;

typedef struct FSSHeader FSSHeader;

typedef struct JournalFile JournalFile;
typedef struct JournalAuthContext JournalAuthContext;

/* Object types */
typedef enum ObjectType {
        OBJECT_UNUSED, /* also serves as "any type" or "additional category" */
        OBJECT_DATA,
        OBJECT_FIELD,
        OBJECT_ENTRY,
        OBJECT_DATA_HASH_TABLE,
        OBJECT_FIELD_HASH_TABLE,
        OBJECT_ENTRY_ARRAY,
        OBJECT_TAG,
        OBJECT_CONTEXT,
        OBJECT_INDEX,
        _OBJECT_TYPE_MAX,
        _OBJECT_TYPE_INVALID = -EINVAL,
} ObjectType;

/* Object flags (note that src/basic/compress.h uses the same values for the compression types) */
enum {
        OBJECT_COMPRESSED_XZ    = 1 << 0,
        OBJECT_COMPRESSED_LZ4   = 1 << 1,
        OBJECT_COMPRESSED_ZSTD  = 1 << 2,
        _OBJECT_COMPRESSED_MASK = OBJECT_COMPRESSED_XZ | OBJECT_COMPRESSED_LZ4 | OBJECT_COMPRESSED_ZSTD,
        OBJECT_UNINDEXED        = 1 << 3, /* segmented files: data object without a data table item */
};

struct ObjectHeader {
        uint8_t type;
        uint8_t flags;
        le16_t aux;      /* segmented files: number of items of entry and context objects, otherwise 0 */
        le32_t checksum; /* segmented files: checksum of the object, otherwise 0 */
        le64_t size;
        uint8_t payload[0]; /* The struct is embedded in other objects, hence flex array (i.e. payload[])
                             * cannot be used. */
} _packed_;

#define DataObject__contents {                                          \
        ObjectHeader object;                                            \
        le64_t hash;                                                    \
        le64_t next_hash_offset;                                        \
        le64_t next_field_offset;                                       \
        le64_t entry_offset; /* the first array entry we store inline */ \
        le64_t entry_array_offset;                                      \
        le64_t n_entries;                                               \
        union {                                                         \
                struct {                                                \
                        uint8_t payload[0];                             \
                } regular;                                              \
                struct {                                                \
                        le32_t tail_entry_array_offset;                 \
                        le32_t tail_entry_array_n_entries;              \
                        uint8_t payload[0];                             \
                } compact;                                              \
        };                                                              \
}

struct DataObject DataObject__contents;
struct DataObject__packed DataObject__contents _packed_;
assert_cc(sizeof(struct DataObject) == sizeof(struct DataObject__packed));

#define FieldObject__contents {                 \
        ObjectHeader object;                    \
        le64_t hash;                            \
        le64_t next_hash_offset;                \
        le64_t head_data_offset;                \
        uint8_t payload[];                      \
}

struct FieldObject FieldObject__contents;
struct FieldObject__packed FieldObject__contents _packed_;
assert_cc(sizeof(struct FieldObject) == sizeof(struct FieldObject__packed));

#define EntryObject__contents {                        \
        ObjectHeader object;                           \
        le64_t seqnum;                                 \
        le64_t realtime;                               \
        le64_t monotonic;                              \
        sd_id128_t boot_id;                            \
        le64_t xor_hash;                               \
        union {                                        \
                struct {                               \
                        le64_t object_offset;          \
                        le64_t hash;                   \
                } regular[0]; /* this is an array; since we are not allowed to place a variable sized array
                               * in a union, we just zero-size it, even if it is generally longer. */ \
                struct {                               \
                        le32_t object_offset;          \
                } compact[0];                          \
        } items;                                       \
}

struct EntryObject EntryObject__contents;
struct EntryObject__packed EntryObject__contents _packed_;
assert_cc(sizeof(struct EntryObject) == sizeof(struct EntryObject__packed));

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
        union {
                DECLARE_FLEX_ARRAY(le64_t, regular);
                DECLARE_FLEX_ARRAY(le32_t, compact);
        } items;
} _packed_;

#define TAG_LENGTH (256/8)

struct TagObject {
        ObjectHeader object;
        le64_t seqnum;
        le64_t epoch;
        uint8_t tag[TAG_LENGTH]; /* SHA-256 HMAC */
} _packed_;

/* Objects of segmented files, see docs/JOURNAL_SEGMENTED.md. */

struct SegmentedDataObject {
        ObjectHeader object;
        le64_t hash;
        uint8_t payload[];
} _packed_;

struct ContextObject {
        ObjectHeader object;
        le32_t items[];
} _packed_;

/* The three low bits of an entry item are its tag. The item with these bits cleared is the offset. */
enum {
        ENTRY_ITEM_DATA    = 0, /* offset of a data object */
        ENTRY_ITEM_CONTEXT = 1, /* offset of a context object */
        ENTRY_ITEM_INLINE  = 2, /* offset of an inline value, relative to the entry object */
        _ENTRY_ITEM_TYPE_MASK = 7,
};

typedef struct InlineData {
        le32_t size;
        uint8_t payload[];
} _packed_ InlineData;

enum {
        INDEX_FIELD_UNINDEXED = 1 << 0, /* the field has data objects without data table items */
        INDEX_FIELD_INLINE    = 1 << 1, /* the field has inline values */
};

struct IndexFieldItem {
        le64_t hash;
        le32_t name_offset;
        le32_t name_size;
        le32_t flags;
        le32_t n_data;
        le32_t first_data;      /* position in the data table */
        le32_t reserved;
} _packed_;

#define INDEX_POSTINGS_ENCODING_SHIFT 30
#define INDEX_POSTINGS_SIZE_MASK ((UINT32_C(1) << INDEX_POSTINGS_ENCODING_SHIFT) - 1)

struct IndexDataItem {
        le64_t hash;
        le64_t hash2;
        le32_t data_offset;
        le32_t n_entries;
        le32_t postings_offset;
        le32_t postings_size; /* the upper two bits are the encoding */
} _packed_;

struct IndexObject {
        ObjectHeader object;
        le64_t head_offset;     /* end of the header, or the offset of the previous index */

        /* The state of the file at the index */
        le64_t n_objects;
        le64_t n_entries;
        le64_t n_data;
        le64_t n_tags;
        le64_t head_entry_seqnum;
        le64_t tail_entry_seqnum;
        le64_t head_entry_realtime;
        le64_t tail_entry_realtime;
        le64_t tail_entry_monotonic;
        sd_id128_t tail_entry_boot_id;
        le64_t tail_entry_offset;

        /* Sections. Offsets are relative to the beginning of the object. */
        le32_t n_index_entries;
        le32_t entry_array_offset;
        le32_t n_fields;
        le32_t field_table_offset;
        le32_t n_data_items;
        le32_t data_table_offset;
        le32_t n_unindexed;
        le32_t unindexed_offset;
        le32_t payload_checksum;
        le32_t reserved;
        uint8_t payload[];
} _packed_;

union Object {
        ObjectHeader object;
        DataObject data;
        FieldObject field;
        EntryObject entry;
        HashTableObject hash_table;
        EntryArrayObject entry_array;
        TagObject tag;
        SegmentedDataObject segmented_data;
        ContextObject context;
        IndexObject index;
};

enum {
        STATE_OFFLINE = 0,
        STATE_ONLINE = 1,
        STATE_ARCHIVED = 2,
        _STATE_MAX,
};

/* Header flags */
enum {
        HEADER_INCOMPATIBLE_COMPRESSED_XZ   = 1 << 0,
        HEADER_INCOMPATIBLE_COMPRESSED_LZ4  = 1 << 1,
        HEADER_INCOMPATIBLE_KEYED_HASH      = 1 << 2,
        HEADER_INCOMPATIBLE_COMPRESSED_ZSTD = 1 << 3,
        HEADER_INCOMPATIBLE_COMPACT         = 1 << 4,
        HEADER_INCOMPATIBLE_SEGMENTED     = 1 << 5,

        HEADER_INCOMPATIBLE_ANY             = HEADER_INCOMPATIBLE_COMPRESSED_XZ |
                                              HEADER_INCOMPATIBLE_COMPRESSED_LZ4 |
                                              HEADER_INCOMPATIBLE_KEYED_HASH |
                                              HEADER_INCOMPATIBLE_COMPRESSED_ZSTD |
                                              HEADER_INCOMPATIBLE_COMPACT |
                                              HEADER_INCOMPATIBLE_SEGMENTED,

        HEADER_INCOMPATIBLE_SUPPORTED       = (HAVE_XZ ? HEADER_INCOMPATIBLE_COMPRESSED_XZ : 0) |
                                              (HAVE_LZ4 ? HEADER_INCOMPATIBLE_COMPRESSED_LZ4 : 0) |
                                              (HAVE_ZSTD ? HEADER_INCOMPATIBLE_COMPRESSED_ZSTD : 0) |
                                              HEADER_INCOMPATIBLE_KEYED_HASH |
                                              HEADER_INCOMPATIBLE_COMPACT |
                                              HEADER_INCOMPATIBLE_SEGMENTED,
};

enum {
        HEADER_COMPATIBLE_SEALED             = 1 << 0,
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID = 1 << 1, /* if set, the last_entry_boot_id field in the header is exclusively refreshed when an entry is appended */
        HEADER_COMPATIBLE_SEALED_CONTINUOUS  = 1 << 2,
        HEADER_COMPATIBLE_ANY                = HEADER_COMPATIBLE_SEALED |
                                               HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID |
                                               HEADER_COMPATIBLE_SEALED_CONTINUOUS,

        HEADER_COMPATIBLE_SUPPORTED          = HEADER_COMPATIBLE_SEALED |
                                               HEADER_COMPATIBLE_SEALED_CONTINUOUS |
                                               HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
};

#define HEADER_SIGNATURE                                                \
        ((const uint8_t[]) { 'L', 'P', 'K', 'S', 'H', 'H', 'R', 'H' })

#define struct_Header__contents {                       \
        uint8_t signature[8]; /* "LPKSHHRH" */          \
        le32_t compatible_flags;                        \
        le32_t incompatible_flags;                      \
        uint8_t state;                                  \
        uint8_t reserved[7];                            \
        sd_id128_t file_id;                             \
        sd_id128_t machine_id;                          \
        sd_id128_t tail_entry_boot_id;                  \
        sd_id128_t seqnum_id;                           \
        le64_t header_size;                             \
        le64_t arena_size;                              \
        le64_t data_hash_table_offset;                  \
        le64_t data_hash_table_size;                    \
        le64_t field_hash_table_offset;                 \
        le64_t field_hash_table_size;                   \
        le64_t tail_object_offset;                      \
        le64_t n_objects;                               \
        le64_t n_entries;                               \
        le64_t tail_entry_seqnum;                       \
        le64_t head_entry_seqnum;                       \
        union {                                         \
                le64_t entry_array_offset;              \
                /* segmented files: the newest index    \
                 * that a sync covered, or 0 */         \
                le64_t synced_index_offset;             \
        };                                              \
        le64_t head_entry_realtime;                     \
        le64_t tail_entry_realtime;                     \
        le64_t tail_entry_monotonic;                    \
        /* Added in 187 */                              \
        le64_t n_data;                                  \
        le64_t n_fields;                                \
        /* Added in 189 */                              \
        le64_t n_tags;                                  \
        le64_t n_entry_arrays;                          \
        /* Added in 246 */                              \
        le64_t data_hash_chain_depth;                   \
        le64_t field_hash_chain_depth;                  \
        /* Added in 252 */                              \
        le32_t tail_entry_array_offset;                 \
        le32_t tail_entry_array_n_entries;              \
        /* Added in 254 */                              \
        le64_t tail_entry_offset;                       \
        }

struct Header struct_Header__contents;
struct Header__packed struct_Header__contents _packed_;
assert_cc(sizeof(struct Header) == sizeof(struct Header__packed));
assert_cc(sizeof(struct Header) == 272);

#define FSS_HEADER_SIGNATURE                                            \
        { 'K', 'S', 'H', 'H', 'R', 'H', 'L', 'P' }

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
