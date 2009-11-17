/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>

#include "set.h"
#include "name.h"
#include "macro.h"
#include "strv.h"

NameType name_type_from_string(const char *n) {
        NameType t;
        static const char* suffixes[_NAME_TYPE_MAX] = {
                [NAME_SERVICE] = ".service",
                [NAME_TIMER] = ".timer",
                [NAME_SOCKET] = ".socket",
                [NAME_MILESTONE] = ".milestone",
                [NAME_DEVICE] = ".device",
                [NAME_MOUNT] = ".mount",
                [NAME_AUTOMOUNT] = ".automount",
                [NAME_SNAPSHOT] = ".snapshot",
        };

        assert(n);

        for (t = 0; t < _NAME_TYPE_MAX; t++)
                if (endswith(n, suffixes[t]))
                        return t;

        return _NAME_TYPE_INVALID;
}

Name *name_new(Manager *m) {
        Name *n;

        assert(m);

        if (!(n = new0(Name, 1)))
                return NULL;

        /* Not much initialization happening here at this time */
        n->meta.manager = m;
        n->meta.type = _NAME_TYPE_INVALID;
        n->meta.state = NAME_STUB;

        /* We don't link the name here, that is left for name_link() */

        return n;
}

int name_link(Name *n) {
        char **t;
        int r;

        assert(n);
        assert(!n->meta.linked);

        STRV_FOREACH(t, n->meta.names)
                if ((r = hashmap_put(n->meta.manager->names, *t, n)) < 0)
                        goto fail;

        if (n->meta.state == NAME_STUB)
                LIST_PREPEND(Meta, n->meta.manager->load_queue, &n->meta);

        n->meta.linked = true;

        return 0;

fail:
        t--;
        STRV_FOREACH_BACKWARDS(t, n->meta.names)
                hashmap_remove(n->meta.manager->names, *t);

        return r;
}

void name_free(Name *name) {

        assert(name);

        /* Detach from next 'bigger' objects */

        if (name->meta.linked) {
                char **t;

                STRV_FOREACH(t, name->meta.names)
                        hashmap_remove(name->meta.manager->names, *t);

                if (name->meta.job)
                        job_free(name->meta.job);
        }

        /* Free data and next 'smaller' objects */

        if (name->meta.job)
                job_free(name->meta.job);

        /* FIXME: Other names pointing to us should probably drop their refs to us when we get destructed */
        set_free(name->meta.requires);
        set_free(name->meta.soft_requires);
        set_free(name->meta.wants);
        set_free(name->meta.requisite);
        set_free(name->meta.soft_requires);
        set_free(name->meta.conflicts);
        set_free(name->meta.before);
        set_free(name->meta.after);

        switch (name->meta.type) {

                case NAME_SOCKET: {
                        unsigned i;
                        Socket *s = SOCKET(name);

                        for (i = 0; i < s->n_fds; i++)
                                nointr_close(s->fds[i]);
                        break;
                }

                case NAME_DEVICE: {
                        Device *d = DEVICE(name);

                        free(d->sysfs);
                        break;
                }

                case NAME_MOUNT: {
                        Mount *m = MOUNT(name);

                        free(m->path);
                        break;
                }

                case NAME_AUTOMOUNT: {
                        Automount *a = AUTOMOUNT(name);

                        free(a->path);
                        break;
                }

                default:
                        ;
        }

        free(name->meta.description);
        strv_free(name->meta.names);

        free(name);
}

bool name_is_ready(Name *name) {

        assert(name);

        if (name->meta.state != NAME_LOADED)
                return false;

        assert(name->meta.type < _NAME_TYPE_MAX);

        switch (name->meta.type) {
                case NAME_SERVICE: {
                        Service *s = SERVICE(name);

                        return
                                s->state == SERVICE_RUNNING ||
                                s->state == SERVICE_RELOAD_PRE ||
                                s->state == SERVICE_RELOAD ||
                                s->state == SERVICE_RELOAD_POST;
                }

                case NAME_TIMER: {
                        Timer *t = TIMER(name);

                        return
                                t->state == TIMER_WAITING ||
                                t->state == TIMER_RUNNING;
                }

                case NAME_SOCKET: {
                        Socket *s = SOCKET(name);

                        return
                                s->state == SOCKET_LISTENING ||
                                s->state == SOCKET_RUNNING;
                }

                case NAME_MILESTONE:
                        return MILESTONE(name)->state == MILESTONE_ACTIVE;

                case NAME_DEVICE:
                        return DEVICE(name)->state == DEVICE_AVAILABLE;

                case NAME_MOUNT:
                        return MOUNT(name)->state == MOUNT_MOUNTED;

                case NAME_AUTOMOUNT: {
                        Automount *a = AUTOMOUNT(name);

                        return
                                a->state == AUTOMOUNT_WAITING ||
                                a->state == AUTOMOUNT_RUNNING;
                }

                case NAME_SNAPSHOT:
                        return SNAPSHOT(name)->state == SNAPSHOT_ACTIVE;


                case _NAME_TYPE_MAX:
                case _NAME_TYPE_INVALID:
                        ;
        }

        assert_not_reached("Unknown name type.");
        return false;
}

static int ensure_in_set(Set **s, void *data) {
        int r;

        assert(s);
        assert(data);

        if (!*s)
                if (!(*s = set_new(trivial_hash_func, trivial_compare_func)))
                        return -ENOMEM;

        if ((r = set_put(*s, data) < 0))
                if (r != -EEXIST)
                        return r;

        return 0;
}

int name_augment(Name *n) {
        int r;
        void* state;
        Name *other;

        assert(n);

        /* Adds in the missing links to make all dependencies both-ways */

        SET_FOREACH(other, n->meta.before, state)
                if ((r = ensure_in_set(&other->meta.after, n) < 0))
                        return r;
        SET_FOREACH(other, n->meta.after, state)
                if ((r = ensure_in_set(&other->meta.before, n) < 0))
                        return r;

        SET_FOREACH(other, n->meta.conflicts, state)
                if ((r = ensure_in_set(&other->meta.conflicts, n) < 0))
                        return r;

        SET_FOREACH(other, n->meta.requires, state)
                if ((r = ensure_in_set(&other->meta.required_by, n) < 0))
                        return r;
        SET_FOREACH(other, n->meta.soft_requires, state)
                if ((r = ensure_in_set(&other->meta.required_by, n) < 0))
                        return r;
        SET_FOREACH(other, n->meta.requisite, state)
                if ((r = ensure_in_set(&other->meta.required_by, n) < 0))
                        return r;
        SET_FOREACH(other, n->meta.soft_requisite, state)
                if ((r = ensure_in_set(&other->meta.required_by, n) < 0))
                        return r;

        return r;
}
