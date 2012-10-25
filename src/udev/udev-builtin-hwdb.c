/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay.sievers@vrfy.org>
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

#include "udev.h"
#include "udev-hwdb.h"

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

struct trie_f {
        struct udev_device *dev;
        bool test;
        FILE *f;
        uint64_t file_time_usec;
        union {
                struct trie_header_f *head;
                const char *map;
        };
        size_t map_size;
};

static const struct trie_child_entry_f *trie_node_children(struct trie_f *trie, const struct trie_node_f *node) {
        return (const struct trie_child_entry_f *)((const char *)node + le64toh(trie->head->node_size));
}

static const struct trie_value_entry_f *trie_node_values(struct trie_f *trie, const struct trie_node_f *node) {
        const char *base = (const char *)node;

        base += le64toh(trie->head->node_size);
        base += node->children_count * le64toh(trie->head->child_entry_size);
        return (const struct trie_value_entry_f *)base;
}

static const struct trie_node_f *trie_node_from_off(struct trie_f *trie, le64_t off) {
        return (const struct trie_node_f *)(trie->map + le64toh(off));
}

static const char *trie_string(struct trie_f *trie, le64_t off) {
        return trie->map + le64toh(off);
}

static int trie_children_cmp_f(const void *v1, const void *v2) {
        const struct trie_child_entry_f *n1 = v1;
        const struct trie_child_entry_f *n2 = v2;

        return n1->c - n2->c;
}

static const struct trie_node_f *node_lookup_f(struct trie_f *trie, const struct trie_node_f *node, uint8_t c) {
        struct trie_child_entry_f *child;
        struct trie_child_entry_f search;

        search.c = c;
        child = bsearch(&search, trie_node_children(trie, node), node->children_count,
                        le64toh(trie->head->child_entry_size), trie_children_cmp_f);
        if (child)
                return trie_node_from_off(trie, child->child_off);
        return NULL;
}

static void trie_fnmatch_f(struct trie_f *trie, const struct trie_node_f *node, size_t p,
                           struct linebuf *buf, const char *search,
                           void (*cb)(struct trie_f *trie, const char *key, const char *value)) {
        size_t len;
        size_t i;
        const char *prefix;

        prefix = trie_string(trie, node->prefix_off);
        len = strlen(prefix + p);
        linebuf_add(buf, prefix + p, len);

        for (i = 0; i < node->children_count; i++) {
                const struct trie_child_entry_f *child = &trie_node_children(trie, node)[i];

                linebuf_add_char(buf, child->c);
                trie_fnmatch_f(trie, trie_node_from_off(trie, child->child_off), 0, buf, search, cb);
                linebuf_rem_char(buf);
        }

        if (node->values_count && fnmatch(linebuf_get(buf), search, 0) == 0)
                for (i = 0; i < node->values_count; i++)
                        cb(trie, trie_string(trie, trie_node_values(trie, node)[i].key_off),
                           trie_string(trie, trie_node_values(trie, node)[i].value_off));

        linebuf_rem(buf, len);
}

static void trie_search_f(struct trie_f *trie, const char *search,
                          void (*cb)(struct trie_f *trie, const char *key, const char *value)) {
        struct linebuf buf;
        const struct trie_node_f *node;
        size_t i = 0;

        linebuf_init(&buf);

        node = trie_node_from_off(trie, trie->head->nodes_root_off);
        while (node) {
                const struct trie_node_f *child;
                size_t p = 0;

                if (node->prefix_off) {
                        uint8_t c;

                        for (; (c = trie_string(trie, node->prefix_off)[p]); p++) {
                                if (c == '*' || c == '?' || c == '[') {
                                        trie_fnmatch_f(trie, node, p, &buf, search + i + p, cb);
                                        return;
                                }
                                if (c != search[i + p])
                                        return;
                        }
                        i += p;
                }

                child = node_lookup_f(trie, node, '*');
                if (child) {
                        linebuf_add_char(&buf, '*');
                        trie_fnmatch_f(trie, child, 0, &buf, search + i, cb);
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(trie, node, '?');
                if (child) {
                        linebuf_add_char(&buf, '?');
                        trie_fnmatch_f(trie, child, 0, &buf, search + i, cb);
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(trie, node, '[');
                if (child) {
                        linebuf_add_char(&buf, '[');
                        trie_fnmatch_f(trie, child, 0, &buf, search + i, cb);
                        linebuf_rem_char(&buf);
                }

                if (search[i] == '\0') {
                        size_t n;

                        for (n = 0; n < node->values_count; n++)
                                cb(trie, trie_string(trie, trie_node_values(trie, node)[n].key_off),
                                   trie_string(trie, trie_node_values(trie, node)[n].value_off));
                        return;
                }

                child = node_lookup_f(trie, node, search[i]);
                node = child;
                i++;
        }
}

static void value_cb(struct trie_f *trie, const char *key, const char *value) {
        /* TODO: add sub-matches (+) against DMI data */
        if (key[0] == ' ')
                udev_builtin_add_property(trie->dev, trie->test, key + 1, value);
}

static struct trie_f trie;

static int hwdb_lookup(struct udev_device *dev, const char *subsys) {
        struct udev_device *d;
        const char *modalias;
        char str[UTIL_NAME_SIZE];
        int rc = EXIT_SUCCESS;

        /* search the first parent device with a modalias */
        for (d = dev; d; d = udev_device_get_parent(d)) {
                const char *dsubsys = udev_device_get_subsystem(d);

                /* look only at devices of a specific subsystem */
                if (subsys && dsubsys && !streq(dsubsys, subsys))
                        continue;

                modalias = udev_device_get_property_value(d, "MODALIAS");
                if (modalias)
                        break;

                /* the usb_device does not have modalias, compose one */
                if (dsubsys && streq(dsubsys, "usb")) {
                        const char *v, *p;
                        int vn, pn;

                        v = udev_device_get_sysattr_value(d, "idVendor");
                        if (!v)
                                continue;
                        p = udev_device_get_sysattr_value(d, "idProduct");
                        if (!p)
                                continue;
                        vn = strtol(v, NULL, 16);
                        if (vn <= 0)
                                continue;
                        pn = strtol(p, NULL, 16);
                        if (pn <= 0)
                                continue;
                        snprintf(str, sizeof(str), "usb:v%04Xp%04X*", vn, pn);
                        modalias = str;
                        break;
                }
        }
        if (!modalias)
                return EXIT_FAILURE;

        trie_search_f(&trie, modalias, value_cb);
        return rc;
}

static int builtin_hwdb(struct udev_device *dev, int argc, char *argv[], bool test) {
        static const struct option options[] = {
                { "subsystem", required_argument, NULL, 's' },
                {}
        };
        const char *subsys = NULL;

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "s", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 's':
                        subsys = optarg;
                        break;
                }
        }

        trie.dev = dev;
        trie.test = test;
        if (hwdb_lookup(dev, subsys) < 0)
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

/* called at udev startup and reload */
static int builtin_hwdb_init(struct udev *udev)
{
        struct stat st;
        const char sig[] = HWDB_SIG;

        trie.f = fopen(SYSCONFDIR "/udev/hwdb.bin", "re");
        if (!trie.f)
                return -errno;

        if (fstat(fileno(trie.f), &st) < 0 || (size_t)st.st_size < offsetof(struct trie_header_f, strings_len) + 8) {
                log_error("Error reading '%s'.", SYSCONFDIR "/udev/hwdb.bin: %m");
                fclose(trie.f);
                zero(trie);
                return -EINVAL;
        }

        trie.map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fileno(trie.f), 0);
        if (trie.map == MAP_FAILED) {
                log_error("Error mapping '%s'.", SYSCONFDIR "/udev/hwdb.bin: %m");
                fclose(trie.f);
                return -EINVAL;
        }
        trie.file_time_usec = ts_usec(&st.st_mtim);
        trie.map_size = st.st_size;

        if (memcmp(trie.map, sig, sizeof(trie.head->signature)) != 0 || (size_t)st.st_size != le64toh(trie.head->file_size)) {
                log_error("Unable to recognize the format of '%s'.", SYSCONFDIR "/udev/hwdb.bin");
                log_error("Please try 'udevadm hwdb --update' to re-create it.");
                munmap((void *)trie.map, st.st_size);
                fclose(trie.f);
                zero(trie);
                return EINVAL;
        }

        log_debug("=== trie on-disk ===\n");
        log_debug("tool version:          %llu", (unsigned long long)le64toh(trie.head->tool_version));
        log_debug("file size:        %8zi bytes\n", st.st_size);
        log_debug("header size       %8zu bytes\n", (size_t)le64toh(trie.head->header_size));
        log_debug("strings           %8zu bytes\n", (size_t)le64toh(trie.head->strings_len));
        log_debug("nodes             %8zu bytes\n", (size_t)le64toh(trie.head->nodes_len));
        return 0;
}

/* called on udev shutdown and reload request */
static void builtin_hwdb_exit(struct udev *udev)
{
        if (!trie.f)
                return;
        munmap((void *)trie.map, trie.map_size);
        fclose(trie.f);
        zero(trie);
}

/* called every couple of seconds during event activity; 'true' if config has changed */
static bool builtin_hwdb_validate(struct udev *udev)
{
        struct stat st;

        if (fstat(fileno(trie.f), &st) < 0)
                return true;
        if (trie.file_time_usec != ts_usec(&st.st_mtim))
                return true;
        return false;
}

const struct udev_builtin udev_builtin_hwdb = {
        .name = "hwdb",
        .cmd = builtin_hwdb,
        .init = builtin_hwdb_init,
        .exit = builtin_hwdb_exit,
        .validate = builtin_hwdb_validate,
        .help = "hardware database",
};
