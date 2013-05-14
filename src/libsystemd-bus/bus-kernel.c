/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <fcntl.h>
#include <malloc.h>
#include <sys/mman.h>

#include "util.h"

#include "bus-internal.h"
#include "bus-message.h"
#include "bus-kernel.h"
#include "bus-bloom.h"

#define KDBUS_ITEM_NEXT(item) \
        (typeof(item))(((uint8_t *)item) + ALIGN8((item)->size))

#define KDBUS_ITEM_FOREACH(item, head)                                          \
        for (item = (head)->items;                                              \
             (uint8_t *)(item) < (uint8_t *)(head) + (head)->size;              \
             item = KDBUS_ITEM_NEXT(item))

#define KDBUS_ITEM_HEADER_SIZE offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) ALIGN8((s) + KDBUS_ITEM_HEADER_SIZE)

#define KDBUS_POOL_SIZE (4*1024*1024)

static int parse_unique_name(const char *s, uint64_t *id) {
        int r;

        assert(s);
        assert(id);

        if (!startswith(s, ":1."))
                return 0;

        r = safe_atou64(s + 3, id);
        if (r < 0)
                return r;

        return 1;
}

static void append_payload_vec(struct kdbus_item **d, const void *p, size_t sz) {
        assert(d);
        assert(p);
        assert(sz > 0);

        *d = ALIGN8_PTR(*d);

        (*d)->size = offsetof(struct kdbus_item, vec) + sizeof(struct kdbus_vec);
        (*d)->type = KDBUS_MSG_PAYLOAD_VEC;
        (*d)->vec.address = (uint64_t) p;
        (*d)->vec.size = sz;

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static void append_destination(struct kdbus_item **d, const char *s, size_t length) {
        assert(d);
        assert(s);

        *d = ALIGN8_PTR(*d);

        (*d)->size = offsetof(struct kdbus_item, str) + length + 1;
        (*d)->type = KDBUS_MSG_DST_NAME;
        memcpy((*d)->str, s, length + 1);

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static void* append_bloom(struct kdbus_item **d, size_t length) {
        void *r;

        assert(d);

        *d = ALIGN8_PTR(*d);

        (*d)->size = offsetof(struct kdbus_item, data) + length;
        (*d)->type = KDBUS_MSG_BLOOM;
        r = (*d)->data;

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);

        return r;
}

static void append_fds(struct kdbus_item **d, const int fds[], unsigned n_fds) {
        assert(d);
        assert(fds);
        assert(n_fds > 0);

        *d = ALIGN8_PTR(*d);
        (*d)->size = offsetof(struct kdbus_item, fds) + sizeof(int) * n_fds;
        (*d)->type = KDBUS_MSG_FDS;
        memcpy((*d)->fds, fds, sizeof(int) * n_fds);

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static int bus_message_setup_bloom(sd_bus_message *m, void *bloom) {
        unsigned i;
        int r;

        assert(m);
        assert(bloom);

        memset(bloom, 0, BLOOM_SIZE);

        bloom_add_pair(bloom, "message-type", bus_message_type_to_string(m->header->type));

        if (m->interface)
                bloom_add_pair(bloom, "interface", m->interface);
        if (m->member)
                bloom_add_pair(bloom, "member", m->member);
        if (m->path) {
                bloom_add_pair(bloom, "path", m->path);
                bloom_add_prefixes(bloom, "path-slash-prefix", m->path, '/');
        }

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return r;

        for (i = 0; i < 64; i++) {
                char type;
                const char *t;
                char buf[sizeof("arg")-1 + 2 + sizeof("-slash-prefix")];
                char *e;

                r = sd_bus_message_peek_type(m, &type, NULL);
                if (r < 0)
                        return r;

                if (type != SD_BUS_TYPE_STRING &&
                    type != SD_BUS_TYPE_OBJECT_PATH &&
                    type != SD_BUS_TYPE_SIGNATURE)
                        break;

                r = sd_bus_message_read_basic(m, type, &t);
                if (r < 0)
                        return r;

                e = stpcpy(buf, "arg");
                if (i < 10)
                        *(e++) = '0' + i;
                else {
                        *(e++) = '0' + (i / 10);
                        *(e++) = '0' + (i % 10);
                }

                *e = 0;
                bloom_add_pair(bloom, buf, t);

                strcpy(e, "-dot-prefix");
                bloom_add_prefixes(bloom, buf, t, '.');
                strcpy(e, "-slash-prefix");
                bloom_add_prefixes(bloom, buf, t, '/');
        }

        return 0;
}

static int bus_message_setup_kmsg(sd_bus *b, sd_bus_message *m) {
        struct kdbus_item *d;
        bool well_known;
        uint64_t unique;
        size_t sz, dl;
        int r;
        struct bus_body_part *part;

        assert(b);
        assert(m);
        assert(m->sealed);

        if (m->kdbus)
                return 0;

        if (m->destination) {
                r = parse_unique_name(m->destination, &unique);
                if (r < 0)
                        return r;

                well_known = r == 0;
        } else
                well_known = false;

        sz = offsetof(struct kdbus_msg, items);

        /* Add in fixed header, fields header and payload */
        sz += (1 + !!m->fields + m->n_body_parts) *
                ALIGN8(offsetof(struct kdbus_item, vec) + sizeof(struct kdbus_vec));

        /* Add space for bloom filter */
        sz += ALIGN8(offsetof(struct kdbus_item, data) + BLOOM_SIZE);

        /* Add in well-known destination header */
        if (well_known) {
                dl = strlen(m->destination);
                sz += ALIGN8(offsetof(struct kdbus_item, str) + dl + 1);
        }

        /* Add space for unix fds */
        if (m->n_fds > 0)
                sz += ALIGN8(offsetof(struct kdbus_item, fds) + sizeof(int)*m->n_fds);

        m->kdbus = memalign(8, sz);
        if (!m->kdbus)
                return -ENOMEM;

        memset(m->kdbus, 0, sz);

        m->kdbus->flags =
                ((m->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED) ? 0 : KDBUS_MSG_FLAGS_EXPECT_REPLY) |
                ((m->header->flags & SD_BUS_MESSAGE_NO_AUTO_START) ? KDBUS_MSG_FLAGS_NO_AUTO_START : 0);
        m->kdbus->dst_id =
                well_known ? 0 :
                m->destination ? unique : KDBUS_DST_ID_BROADCAST;
        m->kdbus->payload_type = KDBUS_PAYLOAD_DBUS1;
        m->kdbus->cookie = m->header->serial;

        m->kdbus->timeout_ns = m->timeout * NSEC_PER_USEC;

        d = m->kdbus->items;

        if (well_known)
                append_destination(&d, m->destination, dl);

        append_payload_vec(&d, m->header, sizeof(*m->header));

        if (m->fields)
                append_payload_vec(&d, m->fields, ALIGN8(m->header->fields_size));

        for (part = &m->body; part && part->size > 0; part = part->next)
                append_payload_vec(&d, part->data, part->size);

        if (m->kdbus->dst_id == KDBUS_DST_ID_BROADCAST) {
                void *p;

                p = append_bloom(&d, BLOOM_SIZE);
                r = bus_message_setup_bloom(m, p);
                if (r < 0) {
                        free(m->kdbus);
                        m->kdbus = NULL;
                        return -r;
                }
        }

        if (m->n_fds > 0)
                append_fds(&d, m->fds, m->n_fds);

        m->kdbus->size = (uint8_t*) d - (uint8_t*) m->kdbus;
        assert(m->kdbus->size <= sz);

        m->free_kdbus = true;

        return 0;
}

int bus_kernel_take_fd(sd_bus *b) {
        uint8_t h[ALIGN8(sizeof(struct kdbus_cmd_hello)) +
                  ALIGN8(KDBUS_ITEM_HEADER_SIZE) +
                  ALIGN8(sizeof(struct kdbus_vec))] = {};

        struct kdbus_cmd_hello *hello = (struct kdbus_cmd_hello*) h;

        int r;

        assert(b);

        if (b->is_server)
                return -EINVAL;

        if (!b->kdbus_buffer) {
                b->kdbus_buffer = mmap(NULL, KDBUS_POOL_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
                if (b->kdbus_buffer == MAP_FAILED) {
                        b->kdbus_buffer = NULL;
                        return -errno;
                }
        }

        hello->size = sizeof(h);
        hello->conn_flags =
                KDBUS_HELLO_ACCEPT_FD|
                KDBUS_HELLO_ATTACH_COMM|
                KDBUS_HELLO_ATTACH_EXE|
                KDBUS_HELLO_ATTACH_CMDLINE|
                KDBUS_HELLO_ATTACH_CGROUP|
                KDBUS_HELLO_ATTACH_CAPS|
                KDBUS_HELLO_ATTACH_SECLABEL|
                KDBUS_HELLO_ATTACH_AUDIT;

        hello->items[0].type = KDBUS_HELLO_POOL;
        hello->items[0].size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
        hello->items[0].vec.address = (uint64_t) b->kdbus_buffer;
        hello->items[0].vec.size = KDBUS_POOL_SIZE;

        r = ioctl(b->input_fd, KDBUS_CMD_HELLO, hello);
        if (r < 0)
                return -errno;

        /* The higher 32bit of both flags fields are considered
         * 'incompatible flags'. Refuse them all for now. */
        if (hello->bus_flags > 0xFFFFFFFFULL ||
            hello->conn_flags > 0xFFFFFFFFULL)
                return -ENOTSUP;

        if (hello->bloom_size != BLOOM_SIZE)
                return -ENOTSUP;

        if (asprintf(&b->unique_name, ":1.%llu", (unsigned long long) hello->id) < 0)
                return -ENOMEM;

        b->is_kernel = true;
        b->bus_client = true;
        b->can_fds = true;

        r = bus_start_running(b);
        if (r < 0)
                return r;

        return 1;
}

int bus_kernel_connect(sd_bus *b) {
        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->kernel);

        if (b->is_server)
                return -EINVAL;

        b->input_fd = open(b->kernel, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (b->input_fd < 0)
                return -errno;

        b->output_fd = b->input_fd;

        return bus_kernel_take_fd(b);
}

int bus_kernel_write_message(sd_bus *bus, sd_bus_message *m) {
        int r;

        assert(bus);
        assert(m);
        assert(bus->state == BUS_RUNNING);

        r = bus_message_setup_kmsg(bus, m);
        if (r < 0)
                return r;

        r = ioctl(bus->output_fd, KDBUS_CMD_MSG_SEND, m->kdbus);
        if (r < 0)
                return errno == EAGAIN ? 0 : -errno;

        return 1;
}

static void close_kdbus_msg(sd_bus *bus, struct kdbus_msg *k) {
        struct kdbus_item *d;

        assert(bus);
        assert(k);

        ioctl(bus->input_fd, KDBUS_CMD_MSG_RELEASE, k);

        KDBUS_ITEM_FOREACH(d, k) {

                if (d->type != KDBUS_MSG_FDS)
                        continue;

                close_many(d->fds, (d->size - offsetof(struct kdbus_item, fds)) / sizeof(int));
        }
}

static bool range_contains(
                size_t astart, size_t asize,
                size_t bstart, size_t bsize,
                void *a, void **b) {

        if (bstart < astart)
                return false;

        if (bstart + bsize > astart + asize)
                return false;

        *b = (uint8_t*) a + (bstart - astart);

        return true;
}

static int bus_kernel_make_message(sd_bus *bus, struct kdbus_msg *k, sd_bus_message **ret) {
        sd_bus_message *m = NULL;
        struct kdbus_item *d;
        unsigned n_payload = 0, n_fds = 0;
        _cleanup_free_ int *fds = NULL;
        struct bus_header *h = NULL;
        size_t total, n_bytes = 0, idx = 0;
        const char *destination = NULL, *seclabel = NULL;
        int r;

        assert(bus);
        assert(k);
        assert(ret);

        if (k->payload_type != KDBUS_PAYLOAD_DBUS1)
                return 0;

        KDBUS_ITEM_FOREACH(d, k) {
                size_t l;

                l = d->size - offsetof(struct kdbus_item, data);

                if (d->type == KDBUS_MSG_PAYLOAD_VEC) {

                        if (!h) {
                                if (d->vec.size < sizeof(struct bus_header))
                                        return -EBADMSG;

                                h = UINT64_TO_PTR(d->vec.address);
                        }

                        n_payload++;
                        n_bytes += d->vec.size;

                } else if (d->type == KDBUS_MSG_FDS) {
                        int *f;
                        unsigned j;

                        j = l / sizeof(int);
                        f = realloc(fds, sizeof(int) * (n_fds + j));
                        if (!f)
                                return -ENOMEM;

                        fds = f;
                        memcpy(fds + n_fds, d->fds, sizeof(int) * j);
                        n_fds += j;

                } else if (d->type == KDBUS_MSG_DST_NAME)
                        destination = d->str;
                else if (d->type == KDBUS_MSG_SRC_SECLABEL)
                        seclabel = d->str;
        }

        if (!h)
                return -EBADMSG;

        r = bus_header_size(h, &total);
        if (r < 0)
                return r;

        if (n_bytes != total)
                return -EBADMSG;

        r = bus_message_from_header(h, sizeof(struct bus_header), fds, n_fds, NULL, seclabel, 0, &m);
        if (r < 0)
                return r;

        KDBUS_ITEM_FOREACH(d, k) {
                size_t l;

                l = d->size - offsetof(struct kdbus_item, data);

                if (d->type == KDBUS_MSG_PAYLOAD_VEC) {
                        size_t begin_body;

                        /* Fill in fields material */
                        range_contains(idx, d->vec.size, ALIGN8(sizeof(struct bus_header)), BUS_MESSAGE_FIELDS_SIZE(m),
                                       UINT64_TO_PTR(d->vec.address), &m->fields);

                        begin_body = ALIGN8(sizeof(struct bus_header)) + ALIGN8(BUS_MESSAGE_FIELDS_SIZE(m));

                        if (idx + d->vec.size > begin_body) {
                                struct bus_body_part *part;

                                /* Contains body material */

                                part = message_append_part(m);
                                if (!part) {
                                        sd_bus_message_unref(m);
                                        return -ENOMEM;
                                }

                                if (idx >= begin_body) {
                                        part->data = (void*) d->vec.address;
                                        part->size = d->vec.size;
                                } else {
                                        part->data = (uint8_t*) (uintptr_t) d->vec.address + (begin_body - idx);
                                        part->size = d->vec.size - (begin_body - idx);
                                }

                                part->sealed = true;
                        }

                        idx += d->vec.size;

                } else if (d->type == KDBUS_MSG_SRC_CREDS) {
                        m->pid_starttime = d->creds.starttime / NSEC_PER_USEC;
                        m->uid = d->creds.uid;
                        m->gid = d->creds.gid;
                        m->pid = d->creds.pid;
                        m->tid = d->creds.tid;
                        m->uid_valid = m->gid_valid = true;
                } else if (d->type == KDBUS_MSG_TIMESTAMP) {
                        m->realtime = d->timestamp.realtime_ns / NSEC_PER_USEC;
                        m->monotonic = d->timestamp.monotonic_ns / NSEC_PER_USEC;
                } else if (d->type == KDBUS_MSG_SRC_PID_COMM)
                        m->comm = d->str;
                else if (d->type == KDBUS_MSG_SRC_TID_COMM)
                        m->tid_comm = d->str;
                else if (d->type == KDBUS_MSG_SRC_EXE)
                        m->exe = d->str;
                else if (d->type == KDBUS_MSG_SRC_CMDLINE) {
                        m->cmdline = d->str;
                        m->cmdline_length = l;
                } else if (d->type == KDBUS_MSG_SRC_CGROUP)
                        m->cgroup = d->str;
                else if (d->type == KDBUS_MSG_SRC_AUDIT)
                        m->audit = &d->audit;
                else if (d->type == KDBUS_MSG_SRC_CAPS) {
                        m->capability = d->data;
                        m->capability_size = l;
                } else if (d->type != KDBUS_MSG_FDS &&
                           d->type != KDBUS_MSG_DST_NAME &&
                           d->type != KDBUS_MSG_SRC_SECLABEL)
                        log_debug("Got unknown field from kernel %llu", d->type);
        }

        if ((BUS_MESSAGE_FIELDS_SIZE(m) > 0 && !m->fields)) {
                sd_bus_message_unref(m);
                return -EBADMSG;
        }

        r = bus_message_parse_fields(m);
        if (r < 0) {
                sd_bus_message_unref(m);
                return r;
        }

        if (k->src_id == KDBUS_SRC_ID_KERNEL)
                m->sender = "org.freedesktop.DBus";
        else {
                snprintf(m->sender_buffer, sizeof(m->sender_buffer), ":1.%llu", (unsigned long long) k->src_id);
                m->sender = m->sender_buffer;
        }

        if (!m->destination) {
                if (destination)
                        m->destination = destination;
                else if (k->dst_id != KDBUS_DST_ID_WELL_KNOWN_NAME &&
                         k->dst_id != KDBUS_DST_ID_BROADCAST) {
                        snprintf(m->destination_buffer, sizeof(m->destination_buffer), ":1.%llu", (unsigned long long) k->dst_id);
                        m->destination = m->destination_buffer;
                }
        }

        /* We take possession of the kmsg struct now */
        m->kdbus = k;
        m->bus = sd_bus_ref(bus);
        m->release_kdbus = true;
        m->free_fds = true;

        fds = NULL;

        *ret = m;
        return 1;
}

int bus_kernel_read_message(sd_bus *bus, sd_bus_message **m) {
        struct kdbus_msg *k;
        int r;

        assert(bus);
        assert(m);

        r = ioctl(bus->input_fd, KDBUS_CMD_MSG_RECV, &k);
        if (r < 0) {
                if (errno == EAGAIN)
                        return 0;

                return -errno;
        }


/*                 /\* Let's tell valgrind that there's really no need to */
/*                  * initialize this fully. This should be removed again */
/*                  * when valgrind learned the kdbus ioctls natively. *\/ */
/* #ifdef HAVE_VALGRIND_MEMCHECK_H */
/*                 VALGRIND_MAKE_MEM_DEFINED(k, sz); */
/* #endif */


        r = bus_kernel_make_message(bus, k, m);
        if (r <= 0)
                close_kdbus_msg(bus, k);

        return r < 0 ? r : 1;
}

int bus_kernel_create(const char *name, char **s) {
        struct kdbus_cmd_bus_make *make;
        struct kdbus_item *n, *cg;
        size_t l;
        int fd;
        char *p;

        assert(name);
        assert(s);

        fd = open("/dev/kdbus/control", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        l = strlen(name);
        make = alloca0(offsetof(struct kdbus_cmd_bus_make, items) +
                       KDBUS_ITEM_HEADER_SIZE + sizeof(uint64_t) +
                       KDBUS_ITEM_HEADER_SIZE + DECIMAL_STR_MAX(uid_t) + 1 + l + 1);

        cg = make->items;
        cg->type = KDBUS_MAKE_CGROUP;
        cg->data64[0] = 1;
        cg->size = KDBUS_ITEM_HEADER_SIZE + sizeof(uint64_t);

        n = KDBUS_ITEM_NEXT(cg);
        n->type = KDBUS_MAKE_NAME;
        sprintf(n->str, "%lu-%s", (unsigned long) getuid(), name);
        n->size = KDBUS_ITEM_HEADER_SIZE + strlen(n->str) + 1;

        make->size = offsetof(struct kdbus_cmd_bus_make, items) + cg->size + n->size;
        make->flags = KDBUS_MAKE_POLICY_OPEN;
        make->bus_flags = 0;
        make->bloom_size = BLOOM_SIZE;
        assert_cc(BLOOM_SIZE % 8 == 0);

        p = strjoin("/dev/kdbus/", n->str, "/bus", NULL);
        if (!p)
                return -ENOMEM;

        if (ioctl(fd, KDBUS_CMD_BUS_MAKE, make) < 0) {
                close_nointr_nofail(fd);
                free(p);
                return -errno;
        }

        if (s)
                *s = p;

        return fd;
}

int bus_kernel_pop_memfd(sd_bus *bus, void **address, size_t *size) {
        struct memfd_cache *c;

        assert(address);
        assert(size);

        if (!bus || !bus->is_kernel)
                return -ENOTSUP;

        if (bus->n_memfd_cache <= 0) {
                int fd, r;

                r = ioctl(bus->input_fd, KDBUS_CMD_MEMFD_NEW, &fd);
                if (r < 0)
                        return -errno;

                *address = NULL;
                *size = 0;
                return fd;
        }

        c = &bus->memfd_cache[-- bus->n_memfd_cache];

        assert(c->fd >= 0);
        assert(c->size == 0 || c->address);

        *address = c->address;
        *size = c->size;

        return c->fd;
}

void bus_kernel_push_memfd(sd_bus *bus, int fd, void *address, size_t size) {
        struct memfd_cache *c;

        assert(fd >= 0);
        assert(size == 0 || address);

        if (!bus || !bus->is_kernel ||
            bus->n_memfd_cache >= ELEMENTSOF(bus->memfd_cache)) {

                if (size > 0)
                        assert_se(munmap(address, PAGE_ALIGN(size)) == 0);

                close_nointr_nofail(fd);
                return;
        }

        c = &bus->memfd_cache[bus->n_memfd_cache++];
        c->fd = fd;
        c->address = address;

        /* If overly long, let's return a bit to the OS */
        if (size > MEMFD_CACHE_ITEM_SIZE_MAX) {
                uint64_t sz = MEMFD_CACHE_ITEM_SIZE_MAX;

                ioctl(bus->input_fd, KDBUS_CMD_MEMFD_SIZE_SET, &sz);

                c->size = MEMFD_CACHE_ITEM_SIZE_MAX;
        } else
                c->size = size;
}

void bus_kernel_flush_memfd(sd_bus *b) {
        unsigned i;

        assert(b);

        for (i = 0; i < b->n_memfd_cache; i++) {
                if (b->memfd_cache[i].size > 0)
                        assert_se(munmap(b->memfd_cache[i].address, PAGE_ALIGN(b->memfd_cache[i].size)) == 0);

                close_nointr_nofail(b->memfd_cache[i].fd);
        }
}
