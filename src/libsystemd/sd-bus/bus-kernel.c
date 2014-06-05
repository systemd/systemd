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
#include <sys/prctl.h>

#include "util.h"
#include "strv.h"

#include "bus-internal.h"
#include "bus-message.h"
#include "bus-kernel.h"
#include "bus-bloom.h"
#include "bus-util.h"
#include "bus-label.h"
#include "cgroup-util.h"

#define UNIQUE_NAME_MAX (3+DECIMAL_STR_MAX(uint64_t))

int bus_kernel_parse_unique_name(const char *s, uint64_t *id) {
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
        assert(sz > 0);

        *d = ALIGN8_PTR(*d);

        /* Note that p can be NULL, which encodes a region full of
         * zeroes, which is useful to optimize certain padding
         * conditions */

        (*d)->size = offsetof(struct kdbus_item, vec) + sizeof(struct kdbus_vec);
        (*d)->type = KDBUS_ITEM_PAYLOAD_VEC;
        (*d)->vec.address = PTR_TO_UINT64(p);
        (*d)->vec.size = sz;

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static void append_payload_memfd(struct kdbus_item **d, int memfd, size_t sz) {
        assert(d);
        assert(memfd >= 0);
        assert(sz > 0);

        *d = ALIGN8_PTR(*d);
        (*d)->size = offsetof(struct kdbus_item, memfd) + sizeof(struct kdbus_memfd);
        (*d)->type = KDBUS_ITEM_PAYLOAD_MEMFD;
        (*d)->memfd.fd = memfd;
        (*d)->memfd.size = sz;

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static void append_destination(struct kdbus_item **d, const char *s, size_t length) {
        assert(d);
        assert(s);

        *d = ALIGN8_PTR(*d);

        (*d)->size = offsetof(struct kdbus_item, str) + length + 1;
        (*d)->type = KDBUS_ITEM_DST_NAME;
        memcpy((*d)->str, s, length + 1);

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static struct kdbus_bloom_filter *append_bloom(struct kdbus_item **d, size_t length) {
        struct kdbus_item *i;

        assert(d);

        i = ALIGN8_PTR(*d);

        i->size = offsetof(struct kdbus_item, bloom_filter) +
                  offsetof(struct kdbus_bloom_filter, data) +
                  length;
        i->type = KDBUS_ITEM_BLOOM_FILTER;

        *d = (struct kdbus_item *) ((uint8_t*) i + i->size);

        return &i->bloom_filter;
}

static void append_fds(struct kdbus_item **d, const int fds[], unsigned n_fds) {
        assert(d);
        assert(fds);
        assert(n_fds > 0);

        *d = ALIGN8_PTR(*d);
        (*d)->size = offsetof(struct kdbus_item, fds) + sizeof(int) * n_fds;
        (*d)->type = KDBUS_ITEM_FDS;
        memcpy((*d)->fds, fds, sizeof(int) * n_fds);

        *d = (struct kdbus_item *) ((uint8_t*) *d + (*d)->size);
}

static int bus_message_setup_bloom(sd_bus_message *m, struct kdbus_bloom_filter *bloom) {
        void *data;
        unsigned i;
        int r;

        assert(m);
        assert(bloom);

        data = bloom->data;
        memzero(data, m->bus->bloom_size);
        bloom->generation = 0;

        bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "message-type", bus_message_type_to_string(m->header->type));

        if (m->interface)
                bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "interface", m->interface);
        if (m->member)
                bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "member", m->member);
        if (m->path) {
                bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "path", m->path);
                bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, "path-slash-prefix", m->path);
                bloom_add_prefixes(data, m->bus->bloom_size, m->bus->bloom_n_hash, "path-slash-prefix", m->path, '/');
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
                        *(e++) = '0' + (char) i;
                else {
                        *(e++) = '0' + (char) (i / 10);
                        *(e++) = '0' + (char) (i % 10);
                }

                *e = 0;
                bloom_add_pair(data, m->bus->bloom_size, m->bus->bloom_n_hash, buf, t);

                strcpy(e, "-dot-prefix");
                bloom_add_prefixes(data, m->bus->bloom_size, m->bus->bloom_n_hash, buf, t, '.');
                strcpy(e, "-slash-prefix");
                bloom_add_prefixes(data, m->bus->bloom_size, m->bus->bloom_n_hash, buf, t, '/');
        }

        return 0;
}

static int bus_message_setup_kmsg(sd_bus *b, sd_bus_message *m) {
        struct bus_body_part *part;
        struct kdbus_item *d;
        bool well_known;
        uint64_t unique;
        size_t sz, dl;
        unsigned i;
        int r;

        assert(b);
        assert(m);
        assert(m->sealed);

        /* We put this together only once, if this message is reused
         * we reuse the earlier-built version */
        if (m->kdbus)
                return 0;

        if (m->destination) {
                r = bus_kernel_parse_unique_name(m->destination, &unique);
                if (r < 0)
                        return r;

                well_known = r == 0;
        } else
                well_known = false;

        sz = offsetof(struct kdbus_msg, items);

        assert_cc(ALIGN8(offsetof(struct kdbus_item, vec) + sizeof(struct kdbus_vec)) ==
                  ALIGN8(offsetof(struct kdbus_item, memfd) + sizeof(struct kdbus_memfd)));

        /* Add in fixed header, fields header and payload */
        sz += (1 + m->n_body_parts) *
                ALIGN8(offsetof(struct kdbus_item, vec) + sizeof(struct kdbus_vec));

        /* Add space for bloom filter */
        sz += ALIGN8(offsetof(struct kdbus_item, bloom_filter) +
                     offsetof(struct kdbus_bloom_filter, data) +
                     m->bus->bloom_size);

        /* Add in well-known destination header */
        if (well_known) {
                dl = strlen(m->destination);
                sz += ALIGN8(offsetof(struct kdbus_item, str) + dl + 1);
        }

        /* Add space for unix fds */
        if (m->n_fds > 0)
                sz += ALIGN8(offsetof(struct kdbus_item, fds) + sizeof(int)*m->n_fds);

        m->kdbus = memalign(8, sz);
        if (!m->kdbus) {
                r = -ENOMEM;
                goto fail;
        }

        m->free_kdbus = true;
        memzero(m->kdbus, sz);

        m->kdbus->flags =
                ((m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED) ? 0 : KDBUS_MSG_FLAGS_EXPECT_REPLY) |
                ((m->header->flags & BUS_MESSAGE_NO_AUTO_START) ? KDBUS_MSG_FLAGS_NO_AUTO_START : 0);
        m->kdbus->dst_id =
                well_known ? 0 :
                m->destination ? unique : KDBUS_DST_ID_BROADCAST;
        m->kdbus->payload_type = KDBUS_PAYLOAD_DBUS;
        m->kdbus->cookie = (uint64_t) m->header->serial;
        m->kdbus->priority = m->priority;

        if (m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                m->kdbus->cookie_reply = m->reply_cookie;
        else
                m->kdbus->timeout_ns = m->timeout * NSEC_PER_USEC;

        d = m->kdbus->items;

        if (well_known)
                append_destination(&d, m->destination, dl);

        append_payload_vec(&d, m->header, BUS_MESSAGE_BODY_BEGIN(m));

        MESSAGE_FOREACH_PART(part, i, m) {
                if (part->is_zero) {
                        /* If this is padding then simply send a
                         * vector with a NULL data pointer which the
                         * kernel will just pass through. This is the
                         * most efficient way to encode zeroes */

                        append_payload_vec(&d, NULL, part->size);
                        continue;
                }

                if (part->memfd >= 0 && part->sealed && m->destination) {
                        /* Try to send a memfd, if the part is
                         * sealed and this is not a broadcast. Since we can only  */

                        append_payload_memfd(&d, part->memfd, part->size);
                        continue;
                }

                /* Otherwise, let's send a vector to the actual data.
                 * For that, we need to map it first. */
                r = bus_body_part_map(part);
                if (r < 0)
                        goto fail;

                append_payload_vec(&d, part->data, part->size);
        }

        if (m->kdbus->dst_id == KDBUS_DST_ID_BROADCAST) {
                struct kdbus_bloom_filter *bloom;

                bloom = append_bloom(&d, m->bus->bloom_size);
                r = bus_message_setup_bloom(m, bloom);
                if (r < 0)
                        goto fail;
        }

        if (m->n_fds > 0)
                append_fds(&d, m->fds, m->n_fds);

        m->kdbus->size = (uint8_t*) d - (uint8_t*) m->kdbus;
        assert(m->kdbus->size <= sz);

        return 0;

fail:
        m->poisoned = true;
        return r;
}

static int bus_kernel_make_message(sd_bus *bus, struct kdbus_msg *k) {
        sd_bus_message *m = NULL;
        struct kdbus_item *d;
        unsigned n_fds = 0;
        _cleanup_free_ int *fds = NULL;
        struct bus_header *h = NULL;
        size_t total, n_bytes = 0, idx = 0;
        const char *destination = NULL, *seclabel = NULL;
        int r;

        assert(bus);
        assert(k);
        assert(k->payload_type == KDBUS_PAYLOAD_DBUS);

        KDBUS_ITEM_FOREACH(d, k, items) {
                size_t l;

                l = d->size - offsetof(struct kdbus_item, data);

                switch (d->type) {

                case KDBUS_ITEM_PAYLOAD_OFF:
                        if (!h) {
                                h = (struct bus_header *)((uint8_t *)k + d->vec.offset);

                                if (!bus_header_is_complete(h, d->vec.size))
                                        return -EBADMSG;
                        }

                        n_bytes += d->vec.size;
                        break;

                case KDBUS_ITEM_PAYLOAD_MEMFD:
                        if (!h)
                                return -EBADMSG;

                        n_bytes += d->memfd.size;
                        break;

                case KDBUS_ITEM_FDS: {
                        int *f;
                        unsigned j;

                        j = l / sizeof(int);
                        f = realloc(fds, sizeof(int) * (n_fds + j));
                        if (!f)
                                return -ENOMEM;

                        fds = f;
                        memcpy(fds + n_fds, d->fds, sizeof(int) * j);
                        n_fds += j;
                        break;
                }

                case KDBUS_ITEM_SECLABEL:
                        seclabel = d->str;
                        break;
                }
        }

        if (!h)
                return -EBADMSG;

        r = bus_header_message_size(h, &total);
        if (r < 0)
                return r;

        if (n_bytes != total)
                return -EBADMSG;

        /* on kdbus we only speak native endian gvariant, never dbus1
         * marshalling or reverse endian */
        if (h->version != 2 ||
            h->endian != BUS_NATIVE_ENDIAN)
                return -EPROTOTYPE;

        r = bus_message_from_header(bus, h, sizeof(struct bus_header), fds, n_fds, NULL, seclabel, 0, &m);
        if (r < 0)
                return r;

        /* The well-known names list is different from the other
        credentials. If we asked for it, but nothing is there, this
        means that the list of well-known names is simply empty, not
        that we lack any data */

        m->creds.mask |= (SD_BUS_CREDS_UNIQUE_NAME|SD_BUS_CREDS_WELL_KNOWN_NAMES) & bus->creds_mask;

        KDBUS_ITEM_FOREACH(d, k, items) {
                size_t l;

                l = d->size - offsetof(struct kdbus_item, data);

                switch (d->type) {

                case KDBUS_ITEM_PAYLOAD_OFF: {
                        size_t begin_body;

                        begin_body = BUS_MESSAGE_BODY_BEGIN(m);

                        if (idx + d->vec.size > begin_body) {
                                struct bus_body_part *part;

                                /* Contains body material */

                                part = message_append_part(m);
                                if (!part) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                /* A -1 offset is NUL padding. */
                                part->is_zero = d->vec.offset == ~0ULL;

                                if (idx >= begin_body) {
                                        if (!part->is_zero)
                                                part->data = (uint8_t *)k + d->vec.offset;
                                        part->size = d->vec.size;
                                } else {
                                        if (!part->is_zero)
                                                part->data = (uint8_t *)k + d->vec.offset + (begin_body - idx);
                                        part->size = d->vec.size - (begin_body - idx);
                                }

                                part->sealed = true;
                        }

                        idx += d->vec.size;
                        break;
                }

                case KDBUS_ITEM_PAYLOAD_MEMFD: {
                        struct bus_body_part *part;

                        if (idx < BUS_MESSAGE_BODY_BEGIN(m)) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        part = message_append_part(m);
                        if (!part) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        part->memfd = d->memfd.fd;
                        part->size = d->memfd.size;
                        part->sealed = true;

                        idx += d->memfd.size;
                        break;
                }

                case KDBUS_ITEM_CREDS:
                        /* UID/GID/PID are always valid */
                        m->creds.uid = (uid_t) d->creds.uid;
                        m->creds.gid = (gid_t) d->creds.gid;
                        m->creds.pid = (pid_t) d->creds.pid;
                        m->creds.mask |= (SD_BUS_CREDS_UID|SD_BUS_CREDS_GID|SD_BUS_CREDS_PID) & bus->creds_mask;

                        /* The PID starttime/TID might be missing
                         * however, when the data is faked by some
                         * data bus proxy and it lacks that
                         * information about the real client since
                         * SO_PEERCRED is used for that */

                        if (d->creds.starttime > 0) {
                                m->creds.pid_starttime = d->creds.starttime / NSEC_PER_USEC;
                                m->creds.mask |= SD_BUS_CREDS_PID_STARTTIME & bus->creds_mask;
                        }

                        if (d->creds.tid > 0) {
                                m->creds.tid = (pid_t) d->creds.tid;
                                m->creds.mask |= SD_BUS_CREDS_TID & bus->creds_mask;
                        }
                        break;

                case KDBUS_ITEM_TIMESTAMP:

                        if (bus->attach_flags & KDBUS_ATTACH_TIMESTAMP) {
                                m->realtime = d->timestamp.realtime_ns / NSEC_PER_USEC;
                                m->monotonic = d->timestamp.monotonic_ns / NSEC_PER_USEC;
                                m->seqnum = d->timestamp.seqnum;
                        }

                        break;

                case KDBUS_ITEM_PID_COMM:
                        m->creds.comm = d->str;
                        m->creds.mask |= SD_BUS_CREDS_COMM & bus->creds_mask;
                        break;

                case KDBUS_ITEM_TID_COMM:
                        m->creds.tid_comm = d->str;
                        m->creds.mask |= SD_BUS_CREDS_TID_COMM & bus->creds_mask;
                        break;

                case KDBUS_ITEM_EXE:
                        m->creds.exe = d->str;
                        m->creds.mask |= SD_BUS_CREDS_EXE & bus->creds_mask;
                        break;

                case KDBUS_ITEM_CMDLINE:
                        m->creds.cmdline = d->str;
                        m->creds.cmdline_size = l;
                        m->creds.mask |= SD_BUS_CREDS_CMDLINE & bus->creds_mask;
                        break;

                case KDBUS_ITEM_CGROUP:
                        m->creds.cgroup = d->str;
                        m->creds.mask |= (SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID) & bus->creds_mask;

                        if (!bus->cgroup_root) {
                                r = cg_get_root_path(&bus->cgroup_root);
                                if (r < 0)
                                        goto fail;
                        }

                        m->creds.cgroup_root = bus->cgroup_root;

                        break;

                case KDBUS_ITEM_AUDIT:
                        m->creds.audit_session_id = (uint32_t) d->audit.sessionid;
                        m->creds.audit_login_uid = (uid_t) d->audit.loginuid;
                        m->creds.mask |= (SD_BUS_CREDS_AUDIT_SESSION_ID|SD_BUS_CREDS_AUDIT_LOGIN_UID) & bus->creds_mask;
                        break;

                case KDBUS_ITEM_CAPS:
                        m->creds.capability = d->data;
                        m->creds.capability_size = l;
                        m->creds.mask |= (SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS) & bus->creds_mask;
                        break;

                case KDBUS_ITEM_DST_NAME:
                        if (!service_name_is_valid(d->str))
                                return -EBADMSG;

                        destination = d->str;
                        break;

                case KDBUS_ITEM_NAME:
                        if (!service_name_is_valid(d->name.name))
                                return -EBADMSG;

                        r = strv_extend(&m->creds.well_known_names, d->name.name);
                        if (r < 0)
                                goto fail;
                        break;

                case KDBUS_ITEM_CONN_NAME:
                        m->creds.conn_name = d->str;
                        m->creds.mask |= SD_BUS_CREDS_CONNECTION_NAME & bus->creds_mask;
                        break;

                case KDBUS_ITEM_FDS:
                case KDBUS_ITEM_SECLABEL:
                        break;

                default:
                        log_debug("Got unknown field from kernel %llu", d->type);
                }
        }

        r = bus_message_parse_fields(m);
        if (r < 0)
                goto fail;

        /* Override information from the user header with data from the kernel */
        if (k->src_id == KDBUS_SRC_ID_KERNEL)
                m->sender = m->creds.unique_name = (char*) "org.freedesktop.DBus";
        else {
                snprintf(m->sender_buffer, sizeof(m->sender_buffer), ":1.%llu", (unsigned long long) k->src_id);
                m->sender = m->creds.unique_name = m->sender_buffer;
        }

        if (destination)
                m->destination = destination;
        else if (k->dst_id == KDBUS_DST_ID_BROADCAST)
                m->destination = NULL;
        else if (k->dst_id == KDBUS_DST_ID_NAME)
                m->destination = bus->unique_name; /* fill in unique name if the well-known name is missing */
        else {
                snprintf(m->destination_buffer, sizeof(m->destination_buffer), ":1.%llu", (unsigned long long) k->dst_id);
                m->destination = m->destination_buffer;
        }

        /* We take possession of the kmsg struct now */
        m->kdbus = k;
        m->release_kdbus = true;
        m->free_fds = true;
        fds = NULL;

        bus->rqueue[bus->rqueue_size++] = m;

        return 1;

fail:
        if (m) {
                struct bus_body_part *part;
                unsigned i;

                /* Make sure the memfds are not freed twice */
                MESSAGE_FOREACH_PART(part, i, m)
                        if (part->memfd >= 0)
                                part->memfd = -1;

                sd_bus_message_unref(m);
        }

        return r;
}

int bus_kernel_take_fd(sd_bus *b) {
        struct kdbus_cmd_hello *hello;
        struct kdbus_item *item;
        _cleanup_free_ char *g = NULL;
        const char *name;
        size_t l = 0, m = 0, sz;
        int r;

        assert(b);

        if (b->is_server)
                return -EINVAL;

        b->use_memfd = 1;

        if (b->connection_name) {
                g = bus_label_escape(b->connection_name);
                if (!g)
                        return -ENOMEM;

                name = g;
        } else {
                char pr[17] = {};

                /* If no name is explicitly set, we'll include a hint
                 * indicating the library implementation, a hint which
                 * kind of bus this is and the thread name */

                assert_se(prctl(PR_GET_NAME, (unsigned long) pr) >= 0);

                if (isempty(pr)) {
                        name = b->is_system ? "sd-system" :
                                b->is_user ? "sd-user" : "sd";
                } else {
                        _cleanup_free_ char *e = NULL;

                        e = bus_label_escape(pr);
                        if (!e)
                                return -ENOMEM;

                        g = strappend(b->is_system ? "sd-system-" :
                                      b->is_user ? "sd-user-" : "sd-",
                                      e);
                        if (!g)
                                return -ENOMEM;

                        name = g;
                }

                b->connection_name = bus_label_unescape(name);
                if (!b->connection_name)
                        return -ENOMEM;
        }

        m = strlen(name);

        sz = ALIGN8(offsetof(struct kdbus_cmd_hello, items)) +
                ALIGN8(offsetof(struct kdbus_item, str) + m + 1);

        if (b->fake_creds_valid)
                sz += ALIGN8(offsetof(struct kdbus_item, creds) + sizeof(struct kdbus_creds));

        if (b->fake_label) {
                l = strlen(b->fake_label);
                sz += ALIGN8(offsetof(struct kdbus_item, str) + l + 1);
        }

        hello = alloca0(sz);
        hello->size = sz;
        hello->conn_flags = b->hello_flags;
        hello->attach_flags = b->attach_flags;
        hello->pool_size = KDBUS_POOL_SIZE;

        item = hello->items;

        item->size = offsetof(struct kdbus_item, str) + m + 1;
        item->type = KDBUS_ITEM_CONN_NAME;
        memcpy(item->str, name, m + 1);
        item = KDBUS_ITEM_NEXT(item);

        if (b->fake_creds_valid) {
                item->size = offsetof(struct kdbus_item, creds) + sizeof(struct kdbus_creds);
                item->type = KDBUS_ITEM_CREDS;
                item->creds = b->fake_creds;

                item = KDBUS_ITEM_NEXT(item);
        }

        if (b->fake_label) {
                item->size = offsetof(struct kdbus_item, str) + l + 1;
                item->type = KDBUS_ITEM_SECLABEL;
                memcpy(item->str, b->fake_label, l+1);
        }

        r = ioctl(b->input_fd, KDBUS_CMD_HELLO, hello);
        if (r < 0)
                return -errno;

        if (!b->kdbus_buffer) {
                b->kdbus_buffer = mmap(NULL, KDBUS_POOL_SIZE, PROT_READ, MAP_SHARED, b->input_fd, 0);
                if (b->kdbus_buffer == MAP_FAILED) {
                        b->kdbus_buffer = NULL;
                        return -errno;
                }
        }

        /* The higher 32bit of both flags fields are considered
         * 'incompatible flags'. Refuse them all for now. */
        if (hello->bus_flags > 0xFFFFFFFFULL ||
            hello->conn_flags > 0xFFFFFFFFULL)
                return -ENOTSUP;

        if (!bloom_validate_parameters((size_t) hello->bloom.size, (unsigned) hello->bloom.n_hash))
                return -ENOTSUP;

        b->bloom_size = (size_t) hello->bloom.size;
        b->bloom_n_hash = (unsigned) hello->bloom.n_hash;

        if (asprintf(&b->unique_name, ":1.%llu", (unsigned long long) hello->id) < 0)
                return -ENOMEM;

        b->unique_id = hello->id;

        b->is_kernel = true;
        b->bus_client = true;
        b->can_fds = !!(hello->conn_flags & KDBUS_HELLO_ACCEPT_FD);
        b->message_version = 2;
        b->message_endian = BUS_NATIVE_ENDIAN;

        /* the kernel told us the UUID of the underlying bus */
        memcpy(b->server_id.bytes, hello->id128, sizeof(b->server_id.bytes));

        return bus_start_running(b);
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

static void close_kdbus_msg(sd_bus *bus, struct kdbus_msg *k) {
        uint64_t off;
        struct kdbus_item *d;

        assert(bus);
        assert(k);

        off = (uint8_t *)k - (uint8_t *)bus->kdbus_buffer;
        ioctl(bus->input_fd, KDBUS_CMD_FREE, &off);

        KDBUS_ITEM_FOREACH(d, k, items) {

                if (d->type == KDBUS_ITEM_FDS)
                        close_many(d->fds, (d->size - offsetof(struct kdbus_item, fds)) / sizeof(int));
                else if (d->type == KDBUS_ITEM_PAYLOAD_MEMFD)
                        safe_close(d->memfd.fd);
        }
}

int bus_kernel_write_message(sd_bus *bus, sd_bus_message *m, bool hint_sync_call) {
        int r;

        assert(bus);
        assert(m);
        assert(bus->state == BUS_RUNNING);

        /* If we can't deliver, we want room for the error message */
        r = bus_rqueue_make_room(bus);
        if (r < 0)
                return r;

        r = bus_message_setup_kmsg(bus, m);
        if (r < 0)
                return r;

        /* If this is a synchronous method call, then let's tell the
         * kernel, so that it can pass CPU time/scheduling to the
         * destination for the time, if it wants to. If we
         * synchronously wait for the result anyway, we won't need CPU
         * anyway. */
        if (hint_sync_call)
                m->kdbus->flags |= KDBUS_MSG_FLAGS_EXPECT_REPLY|KDBUS_MSG_FLAGS_SYNC_REPLY;

        r = ioctl(bus->output_fd, KDBUS_CMD_MSG_SEND, m->kdbus);
        if (r < 0) {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                sd_bus_message *reply;

                if (errno == EAGAIN || errno == EINTR)
                        return 0;
                else if (errno == ENXIO || errno == ESRCH) {

                        /* ENXIO: unique name not known
                         * ESRCH: well-known name not known */

                        if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                                sd_bus_error_setf(&error, SD_BUS_ERROR_SERVICE_UNKNOWN, "Destination %s not known", m->destination);
                        else {
                                log_debug("Could not deliver message to %s as destination is not known. Ignoring.", m->destination);
                                return 0;
                        }

                } else if (errno == EADDRNOTAVAIL) {

                        /* EADDRNOTAVAIL: activation is possible, but turned off in request flags */

                        if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                                sd_bus_error_setf(&error, SD_BUS_ERROR_SERVICE_UNKNOWN, "Activation of %s not requested", m->destination);
                        else {
                                log_debug("Could not deliver message to %s as destination is not activated. Ignoring.", m->destination);
                                return 0;
                        }
                } else
                        return -errno;

                r = bus_message_new_synthetic_error(
                                bus,
                                BUS_MESSAGE_COOKIE(m),
                                &error,
                                &reply);

                if (r < 0)
                        return r;

                r = bus_seal_synthetic_message(bus, reply);
                if (r < 0)
                        return r;

                bus->rqueue[bus->rqueue_size++] = reply;

        } else if (hint_sync_call) {
                struct kdbus_msg *k;

                k = (struct kdbus_msg *)((uint8_t *)bus->kdbus_buffer + m->kdbus->offset_reply);
                assert(k);

                if (k->payload_type == KDBUS_PAYLOAD_DBUS) {

                        r = bus_kernel_make_message(bus, k);
                        if (r < 0) {
                                close_kdbus_msg(bus, k);

                                /* Anybody can send us invalid messages, let's just drop them. */
                                if (r == -EBADMSG || r == -EPROTOTYPE)
                                        log_debug("Ignoring invalid message: %s", strerror(-r));
                                else
                                        return r;
                        }
                } else {
                        log_debug("Ignoring message with unknown payload type %llu.", (unsigned long long) k->payload_type);
                        close_kdbus_msg(bus, k);
                }
        }

        return 1;
}

static int push_name_owner_changed(sd_bus *bus, const char *name, const char *old_owner, const char *new_owner) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "NameOwnerChanged");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "sss", name, old_owner, new_owner);
        if (r < 0)
                return r;

        m->sender = "org.freedesktop.DBus";

        r = bus_seal_synthetic_message(bus, m);
        if (r < 0)
                return r;

        bus->rqueue[bus->rqueue_size++] = m;
        m = NULL;

        return 1;
}

static int translate_name_change(sd_bus *bus, struct kdbus_msg *k, struct kdbus_item *d) {
        char new_owner[UNIQUE_NAME_MAX], old_owner[UNIQUE_NAME_MAX];

        assert(bus);
        assert(k);
        assert(d);

        if (d->type == KDBUS_ITEM_NAME_ADD || (d->name_change.old.flags & (KDBUS_NAME_IN_QUEUE|KDBUS_NAME_ACTIVATOR)))
                old_owner[0] = 0;
        else
                sprintf(old_owner, ":1.%llu", (unsigned long long) d->name_change.old.id);

        if (d->type == KDBUS_ITEM_NAME_REMOVE || (d->name_change.new.flags & (KDBUS_NAME_IN_QUEUE|KDBUS_NAME_ACTIVATOR))) {

                if (isempty(old_owner))
                        return 0;

                new_owner[0] = 0;
        } else
                sprintf(new_owner, ":1.%llu", (unsigned long long) d->name_change.new.id);

        return push_name_owner_changed(bus, d->name_change.name, old_owner, new_owner);
}

static int translate_id_change(sd_bus *bus, struct kdbus_msg *k, struct kdbus_item *d) {
        char owner[UNIQUE_NAME_MAX];

        assert(bus);
        assert(k);
        assert(d);

        sprintf(owner, ":1.%llu", d->id_change.id);

        return push_name_owner_changed(
                        bus, owner,
                        d->type == KDBUS_ITEM_ID_ADD ? NULL : owner,
                        d->type == KDBUS_ITEM_ID_ADD ? owner : NULL);
}

static int translate_reply(sd_bus *bus, struct kdbus_msg *k, struct kdbus_item *d) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(k);
        assert(d);

        r = bus_message_new_synthetic_error(
                        bus,
                        k->cookie_reply,
                        d->type == KDBUS_ITEM_REPLY_TIMEOUT ?
                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Method call timed out") :
                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Method call peer died"),
                        &m);
        if (r < 0)
                return r;

        m->sender = "org.freedesktop.DBus";

        r = bus_seal_synthetic_message(bus, m);
        if (r < 0)
                return r;

        bus->rqueue[bus->rqueue_size++] = m;
        m = NULL;

        return 1;
}

static int bus_kernel_translate_message(sd_bus *bus, struct kdbus_msg *k) {
        struct kdbus_item *d, *found = NULL;

        static int (* const translate[])(sd_bus *bus, struct kdbus_msg *k, struct kdbus_item *d) = {
                [KDBUS_ITEM_NAME_ADD - _KDBUS_ITEM_KERNEL_BASE] = translate_name_change,
                [KDBUS_ITEM_NAME_REMOVE - _KDBUS_ITEM_KERNEL_BASE] = translate_name_change,
                [KDBUS_ITEM_NAME_CHANGE - _KDBUS_ITEM_KERNEL_BASE] = translate_name_change,

                [KDBUS_ITEM_ID_ADD - _KDBUS_ITEM_KERNEL_BASE] = translate_id_change,
                [KDBUS_ITEM_ID_REMOVE - _KDBUS_ITEM_KERNEL_BASE] = translate_id_change,

                [KDBUS_ITEM_REPLY_TIMEOUT - _KDBUS_ITEM_KERNEL_BASE] = translate_reply,
                [KDBUS_ITEM_REPLY_DEAD - _KDBUS_ITEM_KERNEL_BASE] = translate_reply,
        };

        assert(bus);
        assert(k);
        assert(k->payload_type == KDBUS_PAYLOAD_KERNEL);

        KDBUS_ITEM_FOREACH(d, k, items) {
                if (d->type >= _KDBUS_ITEM_KERNEL_BASE && d->type < _KDBUS_ITEM_KERNEL_BASE + ELEMENTSOF(translate)) {
                        if (found)
                                return -EBADMSG;
                        found = d;
                } else
                        log_debug("Got unknown field from kernel %llu", d->type);
        }

        if (!found) {
                log_debug("Didn't find a kernel message to translate.");
                return 0;
        }

        return translate[found->type - _KDBUS_ITEM_KERNEL_BASE](bus, k, found);
}

int bus_kernel_read_message(sd_bus *bus, bool hint_priority, int64_t priority) {
        struct kdbus_cmd_recv recv = {};
        struct kdbus_msg *k;
        int r;

        assert(bus);

        r = bus_rqueue_make_room(bus);
        if (r < 0)
                return r;

        if (hint_priority) {
                recv.flags |= KDBUS_RECV_USE_PRIORITY;
                recv.priority = priority;
        }

        r = ioctl(bus->input_fd, KDBUS_CMD_MSG_RECV, &recv);
        if (r < 0) {
                if (errno == EAGAIN)
                        return 0;

                return -errno;
        }

        k = (struct kdbus_msg *)((uint8_t *)bus->kdbus_buffer + recv.offset);
        if (k->payload_type == KDBUS_PAYLOAD_DBUS) {
                r = bus_kernel_make_message(bus, k);

                /* Anybody can send us invalid messages, let's just drop them. */
                if (r == -EBADMSG || r == -EPROTOTYPE) {
                        log_debug("Ignoring invalid message: %s", strerror(-r));
                        r = 0;
                }

        } else if (k->payload_type == KDBUS_PAYLOAD_KERNEL)
                r = bus_kernel_translate_message(bus, k);
        else {
                log_debug("Ignoring message with unknown payload type %llu.", (unsigned long long) k->payload_type);
                r = 0;
        }

        if (r <= 0)
                close_kdbus_msg(bus, k);

        return r < 0 ? r : 1;
}

int bus_kernel_pop_memfd(sd_bus *bus, void **address, size_t *mapped, size_t *allocated) {
        struct memfd_cache *c;
        int fd;

        assert(address);
        assert(mapped);
        assert(allocated);

        if (!bus || !bus->is_kernel)
                return -ENOTSUP;

        assert_se(pthread_mutex_lock(&bus->memfd_cache_mutex) >= 0);

        if (bus->n_memfd_cache <= 0) {
                _cleanup_free_ char *g = NULL;
                struct kdbus_cmd_memfd_make *cmd;
                struct kdbus_item *item;
                size_t l, sz;
                int r;

                assert_se(pthread_mutex_unlock(&bus->memfd_cache_mutex) >= 0);

                assert(bus->connection_name);

                g = bus_label_escape(bus->connection_name);
                if (!g)
                        return -ENOMEM;

                l = strlen(g);
                sz = ALIGN8(offsetof(struct kdbus_cmd_memfd_make, items)) +
                        ALIGN8(offsetof(struct kdbus_item, str)) +
                        l + 1;
                cmd = alloca0(sz);
                cmd->size = sz;

                item = cmd->items;
                item->size = ALIGN8(offsetof(struct kdbus_item, str)) + l + 1;
                item->type = KDBUS_ITEM_MEMFD_NAME;
                memcpy(item->str, g, l + 1);

                r = ioctl(bus->input_fd, KDBUS_CMD_MEMFD_NEW, cmd);
                if (r < 0)
                        return -errno;

                *address = NULL;
                *mapped = 0;
                *allocated = 0;
                return cmd->fd;
        }

        c = &bus->memfd_cache[--bus->n_memfd_cache];

        assert(c->fd >= 0);
        assert(c->mapped == 0 || c->address);

        *address = c->address;
        *mapped = c->mapped;
        *allocated = c->allocated;
        fd = c->fd;

        assert_se(pthread_mutex_unlock(&bus->memfd_cache_mutex) >= 0);

        return fd;
}

static void close_and_munmap(int fd, void *address, size_t size) {
        if (size > 0)
                assert_se(munmap(address, PAGE_ALIGN(size)) >= 0);

        safe_close(fd);
}

void bus_kernel_push_memfd(sd_bus *bus, int fd, void *address, size_t mapped, size_t allocated) {
        struct memfd_cache *c;
        uint64_t max_mapped = PAGE_ALIGN(MEMFD_CACHE_ITEM_SIZE_MAX);

        assert(fd >= 0);
        assert(mapped == 0 || address);

        if (!bus || !bus->is_kernel) {
                close_and_munmap(fd, address, mapped);
                return;
        }

        assert_se(pthread_mutex_lock(&bus->memfd_cache_mutex) >= 0);

        if (bus->n_memfd_cache >= ELEMENTSOF(bus->memfd_cache)) {
                assert_se(pthread_mutex_unlock(&bus->memfd_cache_mutex) >= 0);

                close_and_munmap(fd, address, mapped);
                return;
        }

        c = &bus->memfd_cache[bus->n_memfd_cache++];
        c->fd = fd;
        c->address = address;

        /* If overly long, let's return a bit to the OS */
        if (mapped > max_mapped) {
                assert_se(ioctl(fd, KDBUS_CMD_MEMFD_SIZE_SET, &max_mapped) >= 0);
                assert_se(munmap((uint8_t*) address + max_mapped, PAGE_ALIGN(mapped - max_mapped)) >= 0);
                c->mapped = c->allocated = max_mapped;
        } else {
                c->mapped = mapped;
                c->allocated = allocated;
        }

        assert_se(pthread_mutex_unlock(&bus->memfd_cache_mutex) >= 0);
}

void bus_kernel_flush_memfd(sd_bus *b) {
        unsigned i;

        assert(b);

        for (i = 0; i < b->n_memfd_cache; i++)
                close_and_munmap(b->memfd_cache[i].fd, b->memfd_cache[i].address, b->memfd_cache[i].mapped);
}

int kdbus_translate_request_name_flags(uint64_t flags, uint64_t *kdbus_flags) {
        uint64_t f = 0;

        assert(kdbus_flags);

        if (flags & SD_BUS_NAME_ALLOW_REPLACEMENT)
                f |= KDBUS_NAME_ALLOW_REPLACEMENT;

        if (flags & SD_BUS_NAME_REPLACE_EXISTING)
                f |= KDBUS_NAME_REPLACE_EXISTING;

        if (flags & SD_BUS_NAME_QUEUE)
                f |= KDBUS_NAME_QUEUE;

        *kdbus_flags = f;
        return 0;
}

int kdbus_translate_attach_flags(uint64_t mask, uint64_t *kdbus_mask) {
        uint64_t m = 0;

        assert(kdbus_mask);

        if (mask & (SD_BUS_CREDS_UID|SD_BUS_CREDS_GID|SD_BUS_CREDS_PID|SD_BUS_CREDS_PID_STARTTIME|SD_BUS_CREDS_TID))
                m |= KDBUS_ATTACH_CREDS;

        if (mask & (SD_BUS_CREDS_COMM|SD_BUS_CREDS_TID_COMM))
                m |= KDBUS_ATTACH_COMM;

        if (mask & SD_BUS_CREDS_EXE)
                m |= KDBUS_ATTACH_EXE;

        if (mask & SD_BUS_CREDS_CMDLINE)
                m |= KDBUS_ATTACH_CMDLINE;

        if (mask & (SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID))
                m |= KDBUS_ATTACH_CGROUP;

        if (mask & (SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS))
                m |= KDBUS_ATTACH_CAPS;

        if (mask & SD_BUS_CREDS_SELINUX_CONTEXT)
                m |= KDBUS_ATTACH_SECLABEL;

        if (mask & (SD_BUS_CREDS_AUDIT_SESSION_ID|SD_BUS_CREDS_AUDIT_LOGIN_UID))
                m |= KDBUS_ATTACH_AUDIT;

        if (mask & SD_BUS_CREDS_WELL_KNOWN_NAMES)
                m |= KDBUS_ATTACH_NAMES;

        if (mask & SD_BUS_CREDS_CONNECTION_NAME)
                m |= KDBUS_ATTACH_CONN_NAME;

        *kdbus_mask = m;
        return 0;
}

int bus_kernel_create_bus(const char *name, bool world, char **s) {
        struct kdbus_cmd_make *make;
        struct kdbus_item *n;
        int fd;

        assert(name);
        assert(s);

        fd = open("/dev/kdbus/control", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        make = alloca0(ALIGN8(offsetof(struct kdbus_cmd_make, items) +
                              offsetof(struct kdbus_item, data64) + sizeof(uint64_t) +
                              offsetof(struct kdbus_item, str) +
                              DECIMAL_STR_MAX(uid_t) + 1 + strlen(name) + 1));

        make->size = offsetof(struct kdbus_cmd_make, items);

        n = make->items;
        n->size = offsetof(struct kdbus_item, bloom_parameter) +
                  sizeof(struct kdbus_bloom_parameter);
        n->type = KDBUS_ITEM_BLOOM_PARAMETER;

        n->bloom_parameter.size = DEFAULT_BLOOM_SIZE;
        n->bloom_parameter.n_hash = DEFAULT_BLOOM_N_HASH;

        assert_cc(DEFAULT_BLOOM_SIZE > 0);
        assert_cc(DEFAULT_BLOOM_N_HASH > 0);

        make->size += ALIGN8(n->size);

        n = KDBUS_ITEM_NEXT(n);
        sprintf(n->str, UID_FMT "-%s", getuid(), name);
        n->size = offsetof(struct kdbus_item, str) + strlen(n->str) + 1;
        n->type = KDBUS_ITEM_MAKE_NAME;
        make->size += ALIGN8(n->size);

        make->flags = world ? KDBUS_MAKE_ACCESS_WORLD : 0;

        if (ioctl(fd, KDBUS_CMD_BUS_MAKE, make) < 0) {
                safe_close(fd);
                return -errno;
        }

        /* The higher 32bit of the flags field are considered
         * 'incompatible flags'. Refuse them all for now. */
        if (make->flags > 0xFFFFFFFFULL) {
                safe_close(fd);
                return -ENOTSUP;
        }

        if (s) {
                char *p;

                p = strjoin("/dev/kdbus/", n->str, "/bus", NULL);
                if (!p) {
                        safe_close(fd);
                        return -ENOMEM;
                }

                *s = p;
        }

        return fd;
}

static int bus_kernel_translate_access(BusNamePolicyAccess access) {
        assert(access >= 0);
        assert(access < _BUSNAME_POLICY_ACCESS_MAX);

        switch (access) {

        case BUSNAME_POLICY_ACCESS_SEE:
                return KDBUS_POLICY_SEE;

        case BUSNAME_POLICY_ACCESS_TALK:
                return KDBUS_POLICY_TALK;

        case BUSNAME_POLICY_ACCESS_OWN:
                return KDBUS_POLICY_OWN;

        default:
                assert_not_reached("Unknown policy access");
        }
}

static int bus_kernel_translate_policy(const BusNamePolicy *policy, struct kdbus_item *item) {
        int r;

        assert(policy);
        assert(item);

        switch (policy->type) {

        case BUSNAME_POLICY_TYPE_USER: {
                const char *user = policy->name;
                uid_t uid;

                r = get_user_creds(&user, &uid, NULL, NULL, NULL);
                if (r < 0)
                        return r;

                item->policy_access.type = KDBUS_POLICY_ACCESS_USER;
                item->policy_access.id = uid;
                break;
        }

        case BUSNAME_POLICY_TYPE_GROUP: {
                const char *group = policy->name;
                gid_t gid;

                r = get_group_creds(&group, &gid);
                if (r < 0)
                        return r;

                item->policy_access.type = KDBUS_POLICY_ACCESS_GROUP;
                item->policy_access.id = gid;
                break;
        }

        default:
                assert_not_reached("Unknown policy type");
        }

        item->policy_access.access = bus_kernel_translate_access(policy->access);

        return 0;
}

int bus_kernel_open_bus_fd(const char *bus) {
        char *p;
        int fd;

        p = alloca(strlen("/dev/kdbus/") + DECIMAL_STR_MAX(uid_t) + 1 + strlen(bus) + strlen("/bus") + 1);
        sprintf(p, "/dev/kdbus/" UID_FMT "-%s/bus", getuid(), bus);

        fd = open(p, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return fd;
}

int bus_kernel_make_starter(
                int fd,
                const char *name,
                bool activating,
                bool accept_fd,
                BusNamePolicy *policy,
                BusNamePolicyAccess world_policy) {

        struct kdbus_cmd_hello *hello;
        struct kdbus_item *n;
        size_t policy_cnt = 0;
        BusNamePolicy *po;
        size_t size;
        int r;

        assert(fd >= 0);
        assert(name);

        LIST_FOREACH(policy, po, policy)
                policy_cnt++;

        if (world_policy >= 0)
                policy_cnt++;

        size = ALIGN8(offsetof(struct kdbus_cmd_hello, items)) +
               ALIGN8(offsetof(struct kdbus_item, str) + strlen(name) + 1) +
               policy_cnt * ALIGN8(offsetof(struct kdbus_item, policy_access) + sizeof(struct kdbus_policy_access));

        hello = alloca0(size);

        n = hello->items;
        strcpy(n->str, name);
        n->size = offsetof(struct kdbus_item, str) + strlen(n->str) + 1;
        n->type = KDBUS_ITEM_NAME;
        n = KDBUS_ITEM_NEXT(n);

        LIST_FOREACH(policy, po, policy) {
                n->type = KDBUS_ITEM_POLICY_ACCESS;
                n->size = offsetof(struct kdbus_item, policy_access) + sizeof(struct kdbus_policy_access);

                r = bus_kernel_translate_policy(po, n);
                if (r < 0)
                        return r;

                n = KDBUS_ITEM_NEXT(n);
        }

        if (world_policy >= 0) {
                n->type = KDBUS_ITEM_POLICY_ACCESS;
                n->size = offsetof(struct kdbus_item, policy_access) + sizeof(struct kdbus_policy_access);
                n->policy_access.type = KDBUS_POLICY_ACCESS_WORLD;
                n->policy_access.access = bus_kernel_translate_access(world_policy);
        }

        hello->size = size;
        hello->conn_flags =
                (activating ? KDBUS_HELLO_ACTIVATOR : KDBUS_HELLO_POLICY_HOLDER) |
                (accept_fd ? KDBUS_HELLO_ACCEPT_FD : 0);
        hello->pool_size = KDBUS_POOL_SIZE;
        hello->attach_flags = _KDBUS_ATTACH_ALL;

        if (ioctl(fd, KDBUS_CMD_HELLO, hello) < 0)
                return -errno;

        /* The higher 32bit of both flags fields are considered
         * 'incompatible flags'. Refuse them all for now. */
        if (hello->bus_flags > 0xFFFFFFFFULL ||
            hello->conn_flags > 0xFFFFFFFFULL)
                return -ENOTSUP;

        if (!bloom_validate_parameters((size_t) hello->bloom.size, (unsigned) hello->bloom.n_hash))
                return -ENOTSUP;

        return fd;
}

int bus_kernel_create_domain(const char *name, char **s) {
        struct kdbus_cmd_make *make;
        struct kdbus_item *n;
        int fd;

        assert(name);
        assert(s);

        fd = open("/dev/kdbus/control", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        make = alloca0(ALIGN8(offsetof(struct kdbus_cmd_make, items) +
                              offsetof(struct kdbus_item, str) +
                              strlen(name) + 1));

        n = make->items;
        strcpy(n->str, name);
        n->size = offsetof(struct kdbus_item, str) + strlen(n->str) + 1;
        n->type = KDBUS_ITEM_MAKE_NAME;

        make->size = ALIGN8(offsetof(struct kdbus_cmd_make, items) + n->size);
        make->flags = KDBUS_MAKE_ACCESS_WORLD;

        if (ioctl(fd, KDBUS_CMD_DOMAIN_MAKE, make) < 0) {
                safe_close(fd);
                return -errno;
        }

        /* The higher 32bit of the flags field are considered
         * 'incompatible flags'. Refuse them all for now. */
        if (make->flags > 0xFFFFFFFFULL) {
                safe_close(fd);
                return -ENOTSUP;
        }

        if (s) {
                char *p;

                p = strappend("/dev/kdbus/domain/", name);
                if (!p) {
                        safe_close(fd);
                        return -ENOMEM;
                }

                *s = p;
        }

        return fd;
}

int bus_kernel_create_monitor(const char *bus) {
        struct kdbus_cmd_hello *hello;
        int fd;

        assert(bus);

        fd = bus_kernel_open_bus_fd(bus);
        if (fd < 0)
                return fd;

        hello = alloca0(sizeof(struct kdbus_cmd_hello));
        hello->size = sizeof(struct kdbus_cmd_hello);
        hello->conn_flags = KDBUS_HELLO_ACTIVATOR;
        hello->pool_size = KDBUS_POOL_SIZE;

        if (ioctl(fd, KDBUS_CMD_HELLO, hello) < 0) {
                safe_close(fd);
                return -errno;
        }

        /* The higher 32bit of both flags fields are considered
         * 'incompatible flags'. Refuse them all for now. */
        if (hello->bus_flags > 0xFFFFFFFFULL ||
            hello->conn_flags > 0xFFFFFFFFULL) {
                safe_close(fd);
                return -ENOTSUP;
        }

        return fd;
}

int bus_kernel_try_close(sd_bus *bus) {
        assert(bus);
        assert(bus->is_kernel);

        if (ioctl(bus->input_fd, KDBUS_CMD_BYEBYE) < 0)
                return -errno;

        return 0;
}

int bus_kernel_drop_one(int fd) {
        struct kdbus_cmd_recv recv = {
                .flags = KDBUS_RECV_DROP
        };

        assert(fd >= 0);

        if (ioctl(fd, KDBUS_CMD_MSG_RECV, &recv) < 0)
                return -errno;

        return 0;
}
