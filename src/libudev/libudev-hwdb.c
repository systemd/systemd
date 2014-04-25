/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay@vrfy.org>
  Copyright 2008 Alan Jenkins <alan.christopher.jenkins@googlemail.com>

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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <fnmatch.h>
#include <getopt.h>
#include <sys/mman.h>

#include "libudev-private.h"
#include "libudev-hwdb-def.h"

/**
 * SECTION:libudev-hwdb
 * @short_description: retrieve properties from the hardware database
 *
 * Libudev hardware database interface.
 */

/**
 * udev_hwdb:
 *
 * Opaque object representing the hardware database.
 */
struct udev_hwdb {
        struct udev *udev;
        int refcount;

        FILE *f;
        struct stat st;
        union {
                struct trie_header_f *head;
                const char *map;
        };

        struct udev_list properties_list;
};

struct linebuf {
        char bytes[LINE_MAX];
        size_t size;
        size_t len;
};

static void linebuf_init(struct linebuf *buf) {
        buf->size = 0;
        buf->len = 0;
}

static const char *linebuf_get(struct linebuf *buf) {
        if (buf->len + 1 >= sizeof(buf->bytes))
                return NULL;
        buf->bytes[buf->len] = '\0';
        return buf->bytes;
}

static bool linebuf_add(struct linebuf *buf, const char *s, size_t len) {
        if (buf->len + len >= sizeof(buf->bytes))
                return false;
        memcpy(buf->bytes + buf->len, s, len);
        buf->len += len;
        return true;
}

static bool linebuf_add_char(struct linebuf *buf, char c)
{
        if (buf->len + 1 >= sizeof(buf->bytes))
                return false;
        buf->bytes[buf->len++] = c;
        return true;
}

static void linebuf_rem(struct linebuf *buf, size_t count) {
        assert(buf->len >= count);
        buf->len -= count;
}

static void linebuf_rem_char(struct linebuf *buf) {
        linebuf_rem(buf, 1);
}

static const struct trie_child_entry_f *trie_node_children(struct udev_hwdb *hwdb, const struct trie_node_f *node) {
        return (const struct trie_child_entry_f *)((const char *)node + le64toh(hwdb->head->node_size));
}

static const struct trie_value_entry_f *trie_node_values(struct udev_hwdb *hwdb, const struct trie_node_f *node) {
        const char *base = (const char *)node;

        base += le64toh(hwdb->head->node_size);
        base += node->children_count * le64toh(hwdb->head->child_entry_size);
        return (const struct trie_value_entry_f *)base;
}

static const struct trie_node_f *trie_node_from_off(struct udev_hwdb *hwdb, le64_t off) {
        return (const struct trie_node_f *)(hwdb->map + le64toh(off));
}

static const char *trie_string(struct udev_hwdb *hwdb, le64_t off) {
        return hwdb->map + le64toh(off);
}

static int trie_children_cmp_f(const void *v1, const void *v2) {
        const struct trie_child_entry_f *n1 = v1;
        const struct trie_child_entry_f *n2 = v2;

        return n1->c - n2->c;
}

static const struct trie_node_f *node_lookup_f(struct udev_hwdb *hwdb, const struct trie_node_f *node, uint8_t c) {
        struct trie_child_entry_f *child;
        struct trie_child_entry_f search;

        search.c = c;
        child = bsearch(&search, trie_node_children(hwdb, node), node->children_count,
                        le64toh(hwdb->head->child_entry_size), trie_children_cmp_f);
        if (child)
                return trie_node_from_off(hwdb, child->child_off);
        return NULL;
}

static int hwdb_add_property(struct udev_hwdb *hwdb, const char *key, const char *value) {
        /*
         * Silently ignore all properties which do not start with a
         * space; future extensions might use additional prefixes.
         */
        if (key[0] != ' ')
                return 0;

        if (udev_list_entry_add(&hwdb->properties_list, key+1, value) == NULL)
                return -ENOMEM;
        return 0;
}

static int trie_fnmatch_f(struct udev_hwdb *hwdb, const struct trie_node_f *node, size_t p,
                          struct linebuf *buf, const char *search) {
        size_t len;
        size_t i;
        const char *prefix;
        int err;

        prefix = trie_string(hwdb, node->prefix_off);
        len = strlen(prefix + p);
        linebuf_add(buf, prefix + p, len);

        for (i = 0; i < node->children_count; i++) {
                const struct trie_child_entry_f *child = &trie_node_children(hwdb, node)[i];

                linebuf_add_char(buf, child->c);
                err = trie_fnmatch_f(hwdb, trie_node_from_off(hwdb, child->child_off), 0, buf, search);
                if (err < 0)
                        return err;
                linebuf_rem_char(buf);
        }

        if (le64toh(node->values_count) && fnmatch(linebuf_get(buf), search, 0) == 0)
                for (i = 0; i < le64toh(node->values_count); i++) {
                        err = hwdb_add_property(hwdb, trie_string(hwdb, trie_node_values(hwdb, node)[i].key_off),
                                                trie_string(hwdb, trie_node_values(hwdb, node)[i].value_off));
                        if (err < 0)
                                return err;
                }

        linebuf_rem(buf, len);
        return 0;
}

static int trie_search_f(struct udev_hwdb *hwdb, const char *search) {
        struct linebuf buf;
        const struct trie_node_f *node;
        size_t i = 0;
        int err;

        linebuf_init(&buf);

        node = trie_node_from_off(hwdb, hwdb->head->nodes_root_off);
        while (node) {
                const struct trie_node_f *child;
                size_t p = 0;

                if (node->prefix_off) {
                        uint8_t c;

                        for (; (c = trie_string(hwdb, node->prefix_off)[p]); p++) {
                                if (c == '*' || c == '?' || c == '[')
                                        return trie_fnmatch_f(hwdb, node, p, &buf, search + i + p);
                                if (c != search[i + p])
                                        return 0;
                        }
                        i += p;
                }

                child = node_lookup_f(hwdb, node, '*');
                if (child) {
                        linebuf_add_char(&buf, '*');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(hwdb, node, '?');
                if (child) {
                        linebuf_add_char(&buf, '?');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(hwdb, node, '[');
                if (child) {
                        linebuf_add_char(&buf, '[');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                if (search[i] == '\0') {
                        size_t n;

                        for (n = 0; n < le64toh(node->values_count); n++) {
                                err = hwdb_add_property(hwdb, trie_string(hwdb, trie_node_values(hwdb, node)[n].key_off),
                                                        trie_string(hwdb, trie_node_values(hwdb, node)[n].value_off));
                                if (err < 0)
                                        return err;
                        }
                        return 0;
                }

                child = node_lookup_f(hwdb, node, search[i]);
                node = child;
                i++;
        }
        return 0;
}

/**
 * udev_hwdb_new:
 * @udev: udev library context
 *
 * Create a hardware database context to query properties for devices.
 *
 * Returns: a hwdb context.
 **/
_public_ struct udev_hwdb *udev_hwdb_new(struct udev *udev) {
        struct udev_hwdb *hwdb;
        const char sig[] = HWDB_SIG;

        hwdb = new0(struct udev_hwdb, 1);
        if (!hwdb)
                return NULL;

        hwdb->refcount = 1;
        udev_list_init(udev, &hwdb->properties_list, true);

        hwdb->f = fopen("/etc/udev/hwdb.bin", "re");
        if (!hwdb->f) {
                udev_dbg(udev, "error reading /etc/udev/hwdb.bin: %m");
                udev_hwdb_unref(hwdb);
                return NULL;
        }

        if (fstat(fileno(hwdb->f), &hwdb->st) < 0 ||
            (size_t)hwdb->st.st_size < offsetof(struct trie_header_f, strings_len) + 8) {
                udev_dbg(udev, "error reading /etc/udev/hwdb.bin: %m");
                udev_hwdb_unref(hwdb);
                return NULL;
        }

        hwdb->map = mmap(0, hwdb->st.st_size, PROT_READ, MAP_SHARED, fileno(hwdb->f), 0);
        if (hwdb->map == MAP_FAILED) {
                udev_dbg(udev, "error mapping /etc/udev/hwdb.bin: %m");
                udev_hwdb_unref(hwdb);
                return NULL;
        }

        if (memcmp(hwdb->map, sig, sizeof(hwdb->head->signature)) != 0 ||
            (size_t)hwdb->st.st_size != le64toh(hwdb->head->file_size)) {
                udev_dbg(udev, "error recognizing the format of /etc/udev/hwdb.bin");
                udev_hwdb_unref(hwdb);
                return NULL;
        }

        udev_dbg(udev, "=== trie on-disk ===\n");
        udev_dbg(udev, "tool version:          %"PRIu64, le64toh(hwdb->head->tool_version));
        udev_dbg(udev, "file size:        %8zu bytes\n", hwdb->st.st_size);
        udev_dbg(udev, "header size       %8"PRIu64" bytes\n", le64toh(hwdb->head->header_size));
        udev_dbg(udev, "strings           %8"PRIu64" bytes\n", le64toh(hwdb->head->strings_len));
        udev_dbg(udev, "nodes             %8"PRIu64" bytes\n", le64toh(hwdb->head->nodes_len));
        return hwdb;
}

/**
 * udev_hwdb_ref:
 * @hwdb: context
 *
 * Take a reference of a hwdb context.
 *
 * Returns: the passed enumeration context
 **/
_public_ struct udev_hwdb *udev_hwdb_ref(struct udev_hwdb *hwdb) {
        if (!hwdb)
                return NULL;
        hwdb->refcount++;
        return hwdb;
}

/**
 * udev_hwdb_unref:
 * @hwdb: context
 *
 * Drop a reference of a hwdb context. If the refcount reaches zero,
 * all resources of the hwdb context will be released.
 *
 * Returns: #NULL
 **/
_public_ struct udev_hwdb *udev_hwdb_unref(struct udev_hwdb *hwdb) {
        if (!hwdb)
                return NULL;
        hwdb->refcount--;
        if (hwdb->refcount > 0)
                return NULL;
        if (hwdb->map)
                munmap((void *)hwdb->map, hwdb->st.st_size);
        if (hwdb->f)
                fclose(hwdb->f);
        udev_list_cleanup(&hwdb->properties_list);
        free(hwdb);
        return NULL;
}

bool udev_hwdb_validate(struct udev_hwdb *hwdb) {
        struct stat st;

        if (!hwdb)
                return false;
        if (!hwdb->f)
                return false;
        if (stat("/etc/udev/hwdb.bin", &st) < 0)
                return true;
        if (timespec_load(&hwdb->st.st_mtim) != timespec_load(&st.st_mtim))
                return true;
        return false;
}

/**
 * udev_hwdb_get_properties_list_entry:
 * @hwdb: context
 * @modalias: modalias string
 * @flags: (unused)
 *
 * Lookup a matching device in the hardware database. The lookup key is a
 * modalias string, whose formats are defined for the Linux kernel modules.
 * Examples are: pci:v00008086d00001C2D*, usb:v04F2pB221*. The first entry
 * of a list of retrieved properties is returned.
 *
 * Returns: a udev_list_entry.
 */
_public_ struct udev_list_entry *udev_hwdb_get_properties_list_entry(struct udev_hwdb *hwdb, const char *modalias, unsigned int flags) {
        int err;

        if (!hwdb || !hwdb->f) {
                errno = EINVAL;
                return NULL;
        }

        udev_list_cleanup(&hwdb->properties_list);
        err = trie_search_f(hwdb, modalias);
        if (err < 0) {
                errno = -err;
                return NULL;
        }
        return udev_list_get_entry(&hwdb->properties_list);
}
