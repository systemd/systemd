/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <sys/stat.h>

#include "def.h"
#include "hashmap.h"
#include "sparse-endian.h"

#define HWDB_SIG { 'K', 'S', 'L', 'P', 'H', 'H', 'R', 'H' }

struct sd_hwdb {
        unsigned n_ref;

        FILE *f;
        struct stat st;
        union {
                struct trie_header_f *head;
                const char *map;
        };

        OrderedHashmap *properties;
        Iterator properties_iterator;
        bool properties_modified;
};

/* on-disk trie objects */
struct trie_header_f {
        uint8_t signature[8];

        /* version of tool which created the file */
        le64_t tool_version;
        le64_t file_size;

        /* size of structures to allow them to grow */
        le64_t header_size;
        le64_t node_size;
        le64_t child_entry_size;
        le64_t value_entry_size;

        /* offset of the root trie node */
        le64_t nodes_root_off;

        /* size of the nodes and string section */
        le64_t nodes_len;
        le64_t strings_len;
} _packed_;

struct trie_node_f {
        /* prefix of lookup string, shared by all children  */
        le64_t prefix_off;
        /* size of children entry array appended to the node */
        uint8_t children_count;
        uint8_t padding[7];
        /* size of value entry array appended to the node */
        le64_t values_count;
} _packed_;

/* array of child entries, follows directly the node record */
struct trie_child_entry_f {
        /* index of the child node */
        uint8_t c;
        uint8_t padding[7];
        /* offset of the child node */
        le64_t child_off;
} _packed_;

/* array of value entries, follows directly the node record/child array */
struct trie_value_entry_f {
        le64_t key_off;
        le64_t value_off;
} _packed_;

/* v2 extends v1 with filename and line-number */
struct trie_value_entry2_f {
        le64_t key_off;
        le64_t value_off;
        le64_t filename_off;
        le32_t line_number;
        le16_t file_priority;
        le16_t padding;
} _packed_;

#define hwdb_bin_paths                          \
        "/etc/systemd/hwdb/hwdb.bin\0"          \
        "/etc/udev/hwdb.bin\0"                  \
        "/usr/lib/systemd/hwdb/hwdb.bin\0"      \
        _CONF_PATHS_SPLIT_USR_NULSTR("systemd/hwdb/hwdb.bin") \
        UDEVLIBEXECDIR "/hwdb.bin\0"
