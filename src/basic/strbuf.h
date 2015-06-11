/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include <stdint.h>

struct strbuf {
        char *buf;
        size_t len;
        struct strbuf_node *root;

        size_t nodes_count;
        size_t in_count;
        size_t in_len;
        size_t dedup_len;
        size_t dedup_count;
};

struct strbuf_node {
        size_t value_off;
        size_t value_len;

        struct strbuf_child_entry *children;
        uint8_t children_count;
};

struct strbuf_child_entry {
        uint8_t c;
        struct strbuf_node *child;
};

struct strbuf *strbuf_new(void);
ssize_t strbuf_add_string(struct strbuf *str, const char *s, size_t len);
void strbuf_complete(struct strbuf *str);
void strbuf_cleanup(struct strbuf *str);
