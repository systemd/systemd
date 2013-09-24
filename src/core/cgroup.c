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

#include <fcntl.h>

#include "path-util.h"
#include "special.h"
#include "cgroup-util.h"
#include "cgroup.h"

void cgroup_context_init(CGroupContext *c) {
        assert(c);

        /* Initialize everything to the kernel defaults, assuming the
         * structure is preinitialized to 0 */

        c->cpu_shares = 1024;
        c->memory_limit = (uint64_t) -1;
        c->blockio_weight = 1000;
}

void cgroup_context_free_device_allow(CGroupContext *c, CGroupDeviceAllow *a) {
        assert(c);
        assert(a);

        LIST_REMOVE(CGroupDeviceAllow, device_allow, c->device_allow, a);
        free(a->path);
        free(a);
}

void cgroup_context_free_blockio_device_weight(CGroupContext *c, CGroupBlockIODeviceWeight *w) {
        assert(c);
        assert(w);

        LIST_REMOVE(CGroupBlockIODeviceWeight, device_weights, c->blockio_device_weights, w);
        free(w->path);
        free(w);
}

void cgroup_context_free_blockio_device_bandwidth(CGroupContext *c, CGroupBlockIODeviceBandwidth *b) {
        assert(c);
        assert(b);

        LIST_REMOVE(CGroupBlockIODeviceBandwidth, device_bandwidths, c->blockio_device_bandwidths, b);
        free(b->path);
        free(b);
}

void cgroup_context_done(CGroupContext *c) {
        assert(c);

        while (c->blockio_device_weights)
                cgroup_context_free_blockio_device_weight(c, c->blockio_device_weights);

        while (c->blockio_device_bandwidths)
                cgroup_context_free_blockio_device_bandwidth(c, c->blockio_device_bandwidths);

        while (c->device_allow)
                cgroup_context_free_device_allow(c, c->device_allow);
}

void cgroup_context_dump(CGroupContext *c, FILE* f, const char *prefix) {
        CGroupBlockIODeviceBandwidth *b;
        CGroupBlockIODeviceWeight *w;
        CGroupDeviceAllow *a;

        assert(c);
        assert(f);

        prefix = strempty(prefix);

        fprintf(f,
                "%sCPUAccounting=%s\n"
                "%sBlockIOAccounting=%s\n"
                "%sMemoryAccounting=%s\n"
                "%sCPUShares=%lu\n"
                "%sBlockIOWeight=%lu\n"
                "%sMemoryLimit=%" PRIu64 "\n"
                "%sDevicePolicy=%s\n",
                prefix, yes_no(c->cpu_accounting),
                prefix, yes_no(c->blockio_accounting),
                prefix, yes_no(c->memory_accounting),
                prefix, c->cpu_shares,
                prefix, c->blockio_weight,
                prefix, c->memory_limit,
                prefix, cgroup_device_policy_to_string(c->device_policy));

        LIST_FOREACH(device_allow, a, c->device_allow)
                fprintf(f,
                        "%sDeviceAllow=%s %s%s%s\n",
                        prefix,
                        a->path,
                        a->r ? "r" : "", a->w ? "w" : "", a->m ? "m" : "");

        LIST_FOREACH(device_weights, w, c->blockio_device_weights)
                fprintf(f,
                        "%sBlockIODeviceWeight=%s %lu",
                        prefix,
                        w->path,
                        w->weight);

        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                char buf[FORMAT_BYTES_MAX];

                fprintf(f,
                        "%s%s=%s %s\n",
                        prefix,
                        b->read ? "BlockIOReadBandwidth" : "BlockIOWriteBandwidth",
                        b->path,
                        format_bytes(buf, sizeof(buf), b->bandwidth));
        }
}

static int lookup_blkio_device(const char *p, dev_t *dev) {
        struct stat st;
        int r;

        assert(p);
        assert(dev);

        r = stat(p, &st);
        if (r < 0) {
                log_warning("Couldn't stat device %s: %m", p);
                return -errno;
        }

        if (S_ISBLK(st.st_mode))
                *dev = st.st_rdev;
        else if (major(st.st_dev) != 0) {
                /* If this is not a device node then find the block
                 * device this file is stored on */
                *dev = st.st_dev;

                /* If this is a partition, try to get the originating
                 * block device */
                block_get_whole_disk(*dev, dev);
        } else {
                log_warning("%s is not a block device and file system block device cannot be determined or is not local.", p);
                return -ENODEV;
        }

        return 0;
}

static int whitelist_device(const char *path, const char *node, const char *acc) {
        char buf[2+DECIMAL_STR_MAX(dev_t)*2+2+4];
        struct stat st;
        int r;

        assert(path);
        assert(acc);

        if (stat(node, &st) < 0) {
                log_warning("Couldn't stat device %s", node);
                return -errno;
        }

        if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {
                log_warning("%s is not a device.", node);
                return -ENODEV;
        }

        sprintf(buf,
                "%c %u:%u %s",
                S_ISCHR(st.st_mode) ? 'c' : 'b',
                major(st.st_rdev), minor(st.st_rdev),
                acc);

        r = cg_set_attribute("devices", path, "devices.allow", buf);
        if (r < 0)
                log_warning("Failed to set devices.allow on %s: %s", path, strerror(-r));

        return r;
}

void cgroup_context_apply(CGroupContext *c, CGroupControllerMask mask, const char *path) {
        int r;

        assert(c);
        assert(path);

        if (mask == 0)
                return;

        if (mask & CGROUP_CPU) {
                char buf[DECIMAL_STR_MAX(unsigned long) + 1];

                sprintf(buf, "%lu\n", c->cpu_shares);
                r = cg_set_attribute("cpu", path, "cpu.shares", buf);
                if (r < 0)
                        log_warning("Failed to set cpu.shares on %s: %s", path, strerror(-r));
        }

        if (mask & CGROUP_BLKIO) {
                char buf[MAX3(DECIMAL_STR_MAX(unsigned long)+1,
                              DECIMAL_STR_MAX(dev_t)*2+2+DECIMAL_STR_MAX(unsigned long)*1,
                              DECIMAL_STR_MAX(dev_t)*2+2+DECIMAL_STR_MAX(uint64_t)+1)];
                CGroupBlockIODeviceWeight *w;
                CGroupBlockIODeviceBandwidth *b;

                sprintf(buf, "%lu\n", c->blockio_weight);
                r = cg_set_attribute("blkio", path, "blkio.weight", buf);
                if (r < 0)
                        log_warning("Failed to set blkio.weight on %s: %s", path, strerror(-r));

                /* FIXME: no way to reset this list */
                LIST_FOREACH(device_weights, w, c->blockio_device_weights) {
                        dev_t dev;

                        r = lookup_blkio_device(w->path, &dev);
                        if (r < 0)
                                continue;

                        sprintf(buf, "%u:%u %lu", major(dev), minor(dev), w->weight);
                        r = cg_set_attribute("blkio", path, "blkio.weight_device", buf);
                        if (r < 0)
                                log_error("Failed to set blkio.weight_device on %s: %s", path, strerror(-r));
                }

                /* FIXME: no way to reset this list */
                LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                        const char *a;
                        dev_t dev;

                        r = lookup_blkio_device(b->path, &dev);
                        if (r < 0)
                                continue;

                        a = b->read ? "blkio.throttle.read_bps_device" : "blkio.throttle.write_bps_device";

                        sprintf(buf, "%u:%u %" PRIu64 "\n", major(dev), minor(dev), b->bandwidth);
                        r = cg_set_attribute("blkio", path, a, buf);
                        if (r < 0)
                                log_error("Failed to set %s on %s: %s", a, path, strerror(-r));
                }
        }

        if (mask & CGROUP_MEMORY) {
                if (c->memory_limit != (uint64_t) -1) {
                        char buf[DECIMAL_STR_MAX(uint64_t) + 1];

                        sprintf(buf, "%" PRIu64 "\n", c->memory_limit);
                        r = cg_set_attribute("memory", path, "memory.limit_in_bytes", buf);
                } else
                        r = cg_set_attribute("memory", path, "memory.limit_in_bytes", "-1");

                if (r < 0)
                        log_error("Failed to set memory.limit_in_bytes on %s: %s", path, strerror(-r));
        }

        if (mask & CGROUP_DEVICE) {
                CGroupDeviceAllow *a;

                if (c->device_allow || c->device_policy != CGROUP_AUTO)
                        r = cg_set_attribute("devices", path, "devices.deny", "a");
                else
                        r = cg_set_attribute("devices", path, "devices.allow", "a");
                if (r < 0)
                        log_error("Failed to reset devices.list on %s: %s", path, strerror(-r));

                if (c->device_policy == CGROUP_CLOSED ||
                    (c->device_policy == CGROUP_AUTO && c->device_allow)) {
                        static const char auto_devices[] =
                                "/dev/null\0" "rw\0"
                                "/dev/zero\0" "rw\0"
                                "/dev/full\0" "rw\0"
                                "/dev/random\0" "rw\0"
                                "/dev/urandom\0" "rw\0";

                        const char *x, *y;

                        NULSTR_FOREACH_PAIR(x, y, auto_devices)
                                whitelist_device(path, x, y);
                }

                LIST_FOREACH(device_allow, a, c->device_allow) {
                        char acc[4];
                        unsigned k = 0;

                        if (a->r)
                                acc[k++] = 'r';
                        if (a->w)
                                acc[k++] = 'w';
                        if (a->m)
                                acc[k++] = 'm';

                        if (k == 0)
                                continue;

                        acc[k++] = 0;
                        whitelist_device(path, a->path, acc);
                }
        }
}

CGroupControllerMask cgroup_context_get_mask(CGroupContext *c) {
        CGroupControllerMask mask = 0;

        /* Figure out which controllers we need */

        if (c->cpu_accounting || c->cpu_shares != 1024)
                mask |= CGROUP_CPUACCT | CGROUP_CPU;

        if (c->blockio_accounting ||
            c->blockio_weight != 1000 ||
            c->blockio_device_weights ||
            c->blockio_device_bandwidths)
                mask |= CGROUP_BLKIO;

        if (c->memory_accounting ||
            c->memory_limit != (uint64_t) -1)
                mask |= CGROUP_MEMORY;

        if (c->device_allow || c->device_policy != CGROUP_AUTO)
                mask |= CGROUP_DEVICE;

        return mask;
}

static CGroupControllerMask unit_get_cgroup_mask(Unit *u) {
        CGroupContext *c;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        return cgroup_context_get_mask(c);
}

static CGroupControllerMask unit_get_members_mask(Unit *u) {
        CGroupControllerMask mask = 0;
        Unit *m;
        Iterator i;

        assert(u);

        SET_FOREACH(m, u->dependencies[UNIT_BEFORE], i) {

                if (UNIT_DEREF(m->slice) != u)
                        continue;

                mask |= unit_get_cgroup_mask(m) | unit_get_members_mask(m);
        }

        return mask;
}

static CGroupControllerMask unit_get_siblings_mask(Unit *u) {
        assert(u);

        if (!UNIT_ISSET(u->slice))
                return 0;

        /* Sibling propagation is only relevant for weight-based
         * controllers, so let's mask out everything else */
        return unit_get_members_mask(UNIT_DEREF(u->slice)) &
                (CGROUP_CPU|CGROUP_BLKIO|CGROUP_CPUACCT);
}

static int unit_create_cgroups(Unit *u, CGroupControllerMask mask) {
        char *path = NULL;
        int r;
        bool is_in_hash = false;

        assert(u);

        path = unit_default_cgroup_path(u);
        if (!path)
                return -ENOMEM;

        r = hashmap_put(u->manager->cgroup_unit, path, u);
        if (r == 0)
                is_in_hash = true;

        if (r < 0) {
                log_error("cgroup %s exists already: %s", path, strerror(-r));
                free(path);
                return r;
        }

        /* First, create our own group */
        r = cg_create_everywhere(u->manager->cgroup_supported, mask, path);
        if (r < 0)
                log_error("Failed to create cgroup %s: %s", path, strerror(-r));

        /* Then, possibly move things over */
        if (u->cgroup_path) {
                r = cg_migrate_everywhere(u->manager->cgroup_supported, u->cgroup_path, path);
                if (r < 0)
                        log_error("Failed to migrate cgroup %s: %s", path, strerror(-r));
        }

        if (!is_in_hash) {
                /* And remember the new data */
                free(u->cgroup_path);
                u->cgroup_path = path;
        }

        u->cgroup_realized = true;
        u->cgroup_mask = mask;

        return 0;
}

static int unit_realize_cgroup_now(Unit *u) {
        CGroupControllerMask mask;

        assert(u);

        if (u->in_cgroup_queue) {
                LIST_REMOVE(Unit, cgroup_queue, u->manager->cgroup_queue, u);
                u->in_cgroup_queue = false;
        }

        mask = unit_get_cgroup_mask(u) | unit_get_members_mask(u) | unit_get_siblings_mask(u);
        mask &= u->manager->cgroup_supported;

        if (u->cgroup_realized &&
            u->cgroup_mask == mask)
                return 0;

        /* First, realize parents */
        if (UNIT_ISSET(u->slice))
                unit_realize_cgroup_now(UNIT_DEREF(u->slice));

        /* And then do the real work */
        return unit_create_cgroups(u, mask);
}

static void unit_add_to_cgroup_queue(Unit *u) {

        if (u->in_cgroup_queue)
                return;

        LIST_PREPEND(Unit, cgroup_queue, u->manager->cgroup_queue, u);
        u->in_cgroup_queue = true;
}

unsigned manager_dispatch_cgroup_queue(Manager *m) {
        Unit *i;
        unsigned n = 0;

        while ((i = m->cgroup_queue)) {
                assert(i->in_cgroup_queue);

                if (unit_realize_cgroup_now(i) >= 0)
                        cgroup_context_apply(unit_get_cgroup_context(i), i->cgroup_mask, i->cgroup_path);

                n++;
        }

        return n;
}

static void unit_queue_siblings(Unit *u) {
        Unit *slice;

        /* This adds the siblings of the specified unit and the
         * siblings of all parent units to the cgroup queue. (But
         * neither the specified unit itself nor the parents.) */

        while ((slice = UNIT_DEREF(u->slice))) {
                Iterator i;
                Unit *m;

                SET_FOREACH(m, slice->dependencies[UNIT_BEFORE], i) {
                        if (m == u)
                                continue;

                        if (UNIT_DEREF(m->slice) != slice)
                                continue;

                        unit_add_to_cgroup_queue(m);
                }

                u = slice;
        }
}

int unit_realize_cgroup(Unit *u) {
        CGroupContext *c;
        int r;

        assert(u);

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        /* So, here's the deal: when realizing the cgroups for this
         * unit, we need to first create all parents, but there's more
         * actually: for the weight-based controllers we also need to
         * make sure that all our siblings (i.e. units that are in the
         * same slice as we are) have cgroup too. Otherwise things
         * would become very uneven as each of their processes would
         * get as much resources as all our group together. This call
         * will synchronously create the parent cgroups, but will
         * defer work on the siblings to the next event loop
         * iteration. */

        /* Add all sibling slices to the cgroup queue. */
        unit_queue_siblings(u);

        /* And realize this one now */
        r = unit_realize_cgroup_now(u);

        /* And apply the values */
        if (r >= 0)
                cgroup_context_apply(c, u->cgroup_mask, u->cgroup_path);

        return r;
}

void unit_destroy_cgroup(Unit *u) {
        int r;

        assert(u);

        if (!u->cgroup_path)
                return;

        r = cg_trim_everywhere(u->manager->cgroup_supported, u->cgroup_path, !unit_has_name(u, SPECIAL_ROOT_SLICE));
        if (r < 0)
                log_debug("Failed to destroy cgroup %s: %s", u->cgroup_path, strerror(-r));

        hashmap_remove(u->manager->cgroup_unit, u->cgroup_path);

        free(u->cgroup_path);
        u->cgroup_path = NULL;
        u->cgroup_realized = false;
        u->cgroup_mask = 0;

}

pid_t unit_search_main_pid(Unit *u) {
        _cleanup_fclose_ FILE *f = NULL;
        pid_t pid = 0, npid, mypid;

        assert(u);

        if (!u->cgroup_path)
                return 0;

        if (cg_enumerate_processes(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, &f) < 0)
                return 0;

        mypid = getpid();
        while (cg_read_pid(f, &npid) > 0)  {
                pid_t ppid;

                if (npid == pid)
                        continue;

                /* Ignore processes that aren't our kids */
                if (get_parent_of_pid(npid, &ppid) >= 0 && ppid != mypid)
                        continue;

                if (pid != 0) {
                        /* Dang, there's more than one daemonized PID
                        in this group, so we don't know what process
                        is the main process. */
                        pid = 0;
                        break;
                }

                pid = npid;
        }

        return pid;
}

int manager_setup_cgroup(Manager *m) {
        _cleanup_free_ char *path = NULL;
        int r;
        char *e, *a;

        assert(m);

        /* 0. Be nice to Ingo Molnar #628004 */
        if (path_is_mount_point("/sys/fs/cgroup/systemd", false) <= 0) {
                log_warning("No control group support available, not creating root group.");
                return 0;
        }

        /* 1. Determine hierarchy */
        free(m->cgroup_root);
        m->cgroup_root = NULL;

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &m->cgroup_root);
        if (r < 0) {
                log_error("Cannot determine cgroup we are running in: %s", strerror(-r));
                return r;
        }

        /* Already in /system.slice? If so, let's cut this off again */
        if (m->running_as == SYSTEMD_SYSTEM) {
                e = endswith(m->cgroup_root, "/" SPECIAL_SYSTEM_SLICE);
                if (e)
                        *e = 0;
        }

        /* And make sure to store away the root value without trailing
         * slash, even for the root dir, so that we can easily prepend
         * it everywhere. */
        if (streq(m->cgroup_root, "/"))
                m->cgroup_root[0] = 0;

        /* 2. Show data */
        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_root, NULL, &path);
        if (r < 0) {
                log_error("Cannot find cgroup mount point: %s", strerror(-r));
                return r;
        }

        log_debug("Using cgroup controller " SYSTEMD_CGROUP_CONTROLLER ". File system hierarchy is at %s.", path);

        /* 3. Install agent */
        if (m->running_as == SYSTEMD_SYSTEM) {
                r = cg_install_release_agent(SYSTEMD_CGROUP_CONTROLLER, SYSTEMD_CGROUP_AGENT_PATH);
                if (r < 0)
                        log_warning("Failed to install release agent, ignoring: %s", strerror(-r));
                else if (r > 0)
                        log_debug("Installed release agent.");
                else
                        log_debug("Release agent already installed.");
        }

        /* 4. Realize the system slice and put us in there */
        if (m->running_as == SYSTEMD_SYSTEM) {
                a = strappenda(m->cgroup_root, "/" SPECIAL_SYSTEM_SLICE);
                r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, a, 0);
        } else
                r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_root, 0);
        if (r < 0) {
                log_error("Failed to create root cgroup hierarchy: %s", strerror(-r));
                return r;
        }

        /* 5. And pin it, so that it cannot be unmounted */
        if (m->pin_cgroupfs_fd >= 0)
                close_nointr_nofail(m->pin_cgroupfs_fd);

        m->pin_cgroupfs_fd = open(path, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOCTTY|O_NONBLOCK);
        if (r < 0) {
                log_error("Failed to open pin file: %m");
                return -errno;
        }

        /* 6. Figure out which controllers are supported */
        m->cgroup_supported = cg_mask_supported();

        /* 7.  Always enable hierarchial support if it exists... */
        cg_set_attribute("memory", "/", "memory.use_hierarchy", "1");

        return 0;
}

void manager_shutdown_cgroup(Manager *m, bool delete) {
        assert(m);

        /* We can't really delete the group, since we are in it. But
         * let's trim it. */
        if (delete && m->cgroup_root)
                cg_trim(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_root, false);

        if (m->pin_cgroupfs_fd >= 0) {
                close_nointr_nofail(m->pin_cgroupfs_fd);
                m->pin_cgroupfs_fd = -1;
        }

        free(m->cgroup_root);
        m->cgroup_root = NULL;
}

Unit* manager_get_unit_by_cgroup(Manager *m, const char *cgroup) {
        char *p;
        Unit *u;

        assert(m);
        assert(cgroup);

        u = hashmap_get(m->cgroup_unit, cgroup);
        if (u)
                return u;

        p = strdupa(cgroup);
        for (;;) {
                char *e;

                e = strrchr(p, '/');
                if (e == p || !e)
                        return NULL;

                *e = 0;

                u = hashmap_get(m->cgroup_unit, p);
                if (u)
                        return u;
        }
}

Unit *manager_get_unit_by_pid(Manager *m, pid_t pid) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(m);

        if (pid <= 1)
                return NULL;

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &cgroup);
        if (r < 0)
                return NULL;

        return manager_get_unit_by_cgroup(m, cgroup);
}

int manager_notify_cgroup_empty(Manager *m, const char *cgroup) {
        Unit *u;
        int r;

        assert(m);
        assert(cgroup);

        u = manager_get_unit_by_cgroup(m, cgroup);
        if (u) {
                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, true);
                if (r > 0) {
                        if (UNIT_VTABLE(u)->notify_cgroup_empty)
                                UNIT_VTABLE(u)->notify_cgroup_empty(u);

                        unit_add_to_gc_queue(u);
                }
        }

        return 0;
}

static const char* const cgroup_device_policy_table[_CGROUP_DEVICE_POLICY_MAX] = {
        [CGROUP_AUTO] = "auto",
        [CGROUP_CLOSED] = "closed",
        [CGROUP_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_device_policy, CGroupDevicePolicy);
