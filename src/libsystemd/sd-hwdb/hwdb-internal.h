/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay@vrfy.org>

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
#pragma once

#include "sparse-endian.h"

#define HWDB_SIG { 'K', 'S', 'L', 'P', 'H', 'H', 'R', 'H' }

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
