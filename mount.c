/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>
#include <stdio.h>
#include <mntent.h>

#include "unit.h"
#include "mount.h"
#include "load-fragment.h"
#include "load-fstab.h"
#include "load-dropin.h"
#include "log.h"

static int mount_init(Unit *u) {
        int r;
        Mount *m = MOUNT(u);

        assert(m);

        /* Load a .mount file */
        if ((r = unit_load_fragment(u)) < 0)
                return r;

        /* Load entry from /etc/fstab */
        if ((r = unit_load_fstab(u)) < 0)
                return r;

        /* Load drop-in directory data */
        if ((r = unit_load_dropin(u)) < 0)
                return r;

        return r;
}

static void mount_done(Unit *u) {
        Mount *d = MOUNT(u);

        assert(d);
        free(d->what);
        free(d->where);
}

static void mount_dump(Unit *u, FILE *f, const char *prefix) {

        static const char* const state_table[_MOUNT_STATE_MAX] = {
                [MOUNT_DEAD] = "dead",
                [MOUNT_MOUNTING] = "mounting",
                [MOUNT_MOUNTED] = "mounted",
                [MOUNT_UNMOUNTING] = "unmounting",
                [MOUNT_MAINTAINANCE] = "maintainance"
        };

        Mount *s = MOUNT(u);

        assert(s);

        fprintf(f,
                "%sMount State: %s\n"
                "%sWhere: %s\n"
                "%sWhat: %s\n",
                prefix, state_table[s->state],
                prefix, s->where,
                prefix, s->what);
}

static void mount_shutdown(Manager *m) {
}

static int mount_add_node_links(Mount *m) {
        Unit *device;
        char *e;
        int r;

        assert(m);

        /* Adds in links to the device that this node is based on */

        if (!path_startswith(m->what, "/dev/"))
                return 0;

        if (!(e = unit_name_escape_path("node-", m->what+1, ".device")))
                return -ENOMEM;

        r = manager_load_unit(UNIT(m)->meta.manager, e, &device);
        free(e);

        if (r < 0)
                return r;

        if ((r = unit_add_dependency(UNIT(m), UNIT_AFTER, device)) < 0)
                return r;

        if ((r = unit_add_dependency(UNIT(m), UNIT_REQUIRES, device)) < 0)
                return r;

        if ((r = unit_add_dependency(device, UNIT_WANTS, UNIT(m))) < 0)
                return r;

        return 0;
}

static int mount_add_path_links(Mount *m) {
        Iterator i;
        Unit *other;
        int r;

        /* Adds in link to other mount points, that might lie below or
         * above us in the hierarchy */

        HASHMAP_FOREACH(other, UNIT(m)->meta.manager->units, i) {
                Mount *n;

                if (other->meta.type != UNIT_MOUNT)
                        continue;

                n = MOUNT(other);

                if (path_startswith(m->where, n->where)) {

                        if ((r = unit_add_dependency(UNIT(m), UNIT_AFTER, other)) < 0)
                                return r;

                        if ((r = unit_add_dependency(UNIT(m), UNIT_REQUIRES, other)) < 0)
                                return r;

                } else if (startswith(n->where, m->where)) {

                        if ((r = unit_add_dependency(UNIT(m), UNIT_BEFORE, other)) < 0)
                                return r;

                        if ((r = unit_add_dependency(other, UNIT_REQUIRES, UNIT(m))) < 0)
                                return r;
                }
        }

        return 0;
}

static int mount_add_one(Manager *m, const char *what, const char *where) {
        char *e;
        int r;
        Unit *u;
        bool delete;

        assert(what);
        assert(where);

        /* probably some kind of swap, which we don't cover for now */
        if (where[0] != '/')
                return 0;

        if (streq(where, "/"))
                e = strdup("rootfs.mount");
        else
                e = unit_name_escape_path("fs-", where+1, ".mount");

        if (!e)
                return -ENOMEM;

        if (!(u = manager_get_unit(m, e))) {
                delete = true;

                if (!(u = unit_new(m))) {
                        free(e);
                        return -ENOMEM;
                }

                r = unit_add_name(u, e);
                free(e);

                if (r < 0)
                        goto fail;

                if (!(MOUNT(u)->what = strdup(what)) ||
                    !(MOUNT(u)->where = strdup(where)) ||
                    !(u->meta.description = strdup(where))) {
                        r = -ENOMEM;
                        goto fail;
                }
        } else {
                delete = false;
                free(e);
        }

        if ((r = mount_add_node_links(MOUNT(u))) < 0)
                goto fail;

        if ((r = mount_add_path_links(MOUNT(u))) < 0)
                goto fail;

        unit_add_to_load_queue(u);
        return 0;

fail:
        if (delete && u)
                unit_free(u);

        return 0;
}

static char *fstab_node_to_udev_node(char *p) {
        char *dn, *t;
        int r;

        /* FIXME: to follow udev's logic 100% we need to leave valid
         * UTF8 chars unescaped */

        if (startswith(p, "LABEL=")) {

                if (!(t = strdup(p+6)))
                        return NULL;

                r = asprintf(&dn, "/dev/disk/by-label/%s", xescape(t, "/ "));
                free(t);

                if (r < 0)
                        return NULL;

                return dn;
        }

        if (startswith(p, "UUID=")) {

                if (!(t = strdup(p+5)))
                        return NULL;

                r = asprintf(&dn, "/dev/disk/by-uuid/%s", ascii_strlower(xescape(t, "/ ")));
                free(t);

                if (r < 0)
                        return NULL;

                return dn;
        }

        return strdup(p);
}

static int mount_load_etc_fstab(Manager *m) {
        FILE *f;
        int r;
        struct mntent* me;

        assert(m);

        errno = 0;
        if (!(f = setmntent("/etc/fstab", "r")))
                return -errno;

        while ((me = getmntent(f))) {
                char *where, *what;

                if (!(what = fstab_node_to_udev_node(me->mnt_fsname))) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(where = strdup(me->mnt_dir))) {
                        free(what);
                        r = -ENOMEM;
                        goto finish;
                }

                if (what[0] == '/')
                        path_kill_slashes(what);

                if (where[0] == '/')
                        path_kill_slashes(where);

                r = mount_add_one(m, what, where);
                free(what);
                free(where);

                if (r < 0)
                        goto finish;
        }

        r = 0;
finish:

        endmntent(f);
        return r;
}

static int mount_load_proc_mounts(Manager *m) {
        FILE *f;
        int r;

        assert(m);

        if (!(f = fopen("/proc/self/mountinfo", "r")))
                return -errno;

        for (;;) {
                int k;
                char *device, *path, *d, *p;

                if ((k = fscanf(f,
                                "%*s "       /* (1) mount id */
                                "%*s "       /* (2) parent id */
                                "%*s "       /* (3) major:minor */
                                "%*s "       /* (4) root */
                                "%ms "       /* (5) mount point */
                                "%*s"        /* (6) mount options */
                                "%*[^-]"     /* (7) optional fields */
                                "- "         /* (8) seperator */
                                "%*s "       /* (9) file system type */
                                "%ms"       /* (10) mount source */
                                "%*[^\n]", /* some rubbish at the end */
                                &path,
                                &device)) != 2) {

                        if (k == EOF) {
                                if (feof(f))
                                        break;

                                r = -errno;
                                goto finish;
                        }

                        r = -EBADMSG;
                        goto finish;
                }

                if (!(d = cunescape(device))) {
                        free(device);
                        free(path);
                        r = -ENOMEM;
                        goto finish;
                }
                free(device);

                if (!(p = cunescape(path))) {
                        free(d);
                        free(path);
                        r = -ENOMEM;
                        goto finish;
                }
                free(path);

                r = mount_add_one(m, d, p);
                free(d);
                free(p);

                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        fclose(f);

        return r;
}

static int mount_enumerate(Manager *m) {
        int r;
        assert(m);

        if ((r = mount_load_etc_fstab(m)) < 0)
                goto fail;

        if ((r = mount_load_proc_mounts(m)) < 0)
                goto fail;

        return 0;

fail:
        mount_shutdown(m);
        return r;
}

static UnitActiveState mount_active_state(Unit *u) {

        static const UnitActiveState table[_MOUNT_STATE_MAX] = {
                [MOUNT_DEAD] = UNIT_INACTIVE,
                [MOUNT_MOUNTING] = UNIT_ACTIVATING,
                [MOUNT_MOUNTED] = UNIT_ACTIVE,
                [MOUNT_UNMOUNTING] = UNIT_DEACTIVATING,
                [MOUNT_MAINTAINANCE] = UNIT_INACTIVE,
        };

        return table[MOUNT(u)->state];
}

const UnitVTable mount_vtable = {
        .suffix = ".mount",

        .init = mount_init,
        .done = mount_done,
        .dump = mount_dump,

        .enumerate = mount_enumerate,
        .shutdown = mount_shutdown,

        .active_state = mount_active_state
};
