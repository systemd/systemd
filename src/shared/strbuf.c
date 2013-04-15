/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "strbuf.h"

/*
 * Strbuf stores given strings in a single continuous allocated memory
 * area. Identical strings are de-duplicated and return the same offset
 * as the first string stored. If the tail of a string already exists
 * in the buffer, the tail is returned.
 *
 * A trie (http://en.wikipedia.org/wiki/Trie) is used to maintain the
 * information about the stored strings.
 *
 * Example of udev rules:
 *   $ ./udevadm test .
 *   ...
 *   read rules file: /usr/lib/udev/rules.d/99-systemd.rules
 *   rules contain 196608 bytes tokens (16384 * 12 bytes), 39742 bytes strings
 *   23939 strings (207859 bytes), 20404 de-duplicated (171653 bytes), 3536 trie nodes used
 *   ...
 */

struct strbuf *strbuf_new(void) {
        struct strbuf *str;

        str = new0(struct strbuf, 1);
        if (!str)
                return NULL;

        str->buf = new0(char, 1);
        if (!str->buf)
                goto err;
        str->len = 1;

        str->root = new0(struct strbuf_node, 1);
        if (!str->root)
                goto err;
        str->nodes_count = 1;
        return str;
err:
        free(str->buf);
        free(str->root);
        free(str);
        return NULL;
}

static void strbuf_node_cleanup(struct strbuf_node *node) {
        size_t i;

        for (i = 0; i < node->children_count; i++)
                strbuf_node_cleanup(node->children[i].child);
        free(node->children);
        free(node);
}

/* clean up trie data, leave only the string buffer */
void strbuf_complete(struct strbuf *str) {
        if (!str)
                return;
        if (str->root)
                strbuf_node_cleanup(str->root);
        str->root = NULL;
}

/* clean up everything */
void strbuf_cleanup(struct strbuf *str) {
        if (!str)
                return;
        if (str->root)
                strbuf_node_cleanup(str->root);
        free(str->buf);
        free(str);
}

static int strbuf_children_cmp(const struct strbuf_child_entry *n1,
                               const struct strbuf_child_entry *n2) {
        return n1->c - n2->c;
}

static void bubbleinsert(struct strbuf_node *node,
                         uint8_t c,
                         struct strbuf_node *node_child) {

        struct strbuf_child_entry new = {
                .c = c,
                .child = node_child,
        };
        int left = 0, right = node->children_count;

        while (right > left) {
                int middle = (right + left) / 2 ;
                if (strbuf_children_cmp(&node->children[middle], &new) <= 0)
                        left = middle + 1;
                else
                        right = middle;
        }

        memmove(node->children + left + 1, node->children + left,
                sizeof(struct strbuf_child_entry) * (node->children_count - left));
        node->children[left] = new;

        node->children_count ++;
}

/* add string, return the index/offset into the buffer */
ssize_t strbuf_add_string(struct strbuf *str, const char *s, size_t len) {
        uint8_t c;
        struct strbuf_node *node;
        size_t depth;
        char *buf_new;
        struct strbuf_child_entry *child;
        struct strbuf_node *node_child;
        ssize_t off;

        if (!str->root)
                return -EINVAL;

        /* search string; start from last character to find possibly matching tails */
        if (len == 0)
                return 0;
        str->in_count++;
        str->in_len += len;

        node = str->root;
        c = s[len-1];
        for (depth = 0; depth <= len; depth++) {
                struct strbuf_child_entry search;

                /* match against current node */
                off = node->value_off + node->value_len - len;
                if (depth == len || (node->value_len >= len && memcmp(str->buf + off, s, len) == 0)) {
                        str->dedup_len += len;
                        str->dedup_count++;
                        return off;
                }

                /* lookup child node */
                c = s[len - 1 - depth];
                search.c = c;
                child = bsearch(&search, node->children, node->children_count,
                                sizeof(struct strbuf_child_entry),
                                (__compar_fn_t) strbuf_children_cmp);
                if (!child)
                        break;
                node = child->child;
        }

        /* add new string */
        buf_new = realloc(str->buf, str->len + len+1);
        if (!buf_new)
                return -ENOMEM;
        str->buf = buf_new;
        off = str->len;
        memcpy(str->buf + off, s, len);
        str->len += len;
        str->buf[str->len++] = '\0';

        /* new node */
        node_child = new0(struct strbuf_node, 1);
        if (!node_child)
                return -ENOMEM;
        node_child->value_off = off;
        node_child->value_len = len;

        /* extend array, add new entry, sort for bisection */
        child = realloc(node->children, (node->children_count + 1) * sizeof(struct strbuf_child_entry));
        if (!child) {
                free(node_child);
                return -ENOMEM;
        }

        str->nodes_count++;

        node->children = child;
        bubbleinsert(node, c, node_child);

        return off;
}
