/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "manager.h"
#include "hashmap.h"
#include "macro.h"
#include "strv.h"
#include "load-fragment.h"

Manager* manager_new(void) {
        Manager *m;

        if (!(m = new0(Manager, 1)))
                return NULL;

        if (!(m->names = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        if (!(m->jobs = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->jobs_to_add = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->jobs_to_remove = set_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        return m;

fail:
        manager_free(m);
        return NULL;
}

void manager_free(Manager *m) {
        Name *n;

        assert(m);

        while ((n = hashmap_first(m->names)))
                name_free(n);

        hashmap_free(m->names);
        hashmap_free(m->jobs);

        /* FIXME: This is incomplete */

        hashmap_free(m->jobs_to_add);
        set_free(m->jobs_to_remove);

        free(m);
}

int manager_add_job(Manager *m, JobType type, Name *name, JobMode mode, Job **_ret) {
        Job *ret, *other;
        void *state;
        Name *dep;
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);
        assert(_ret);

        /* Check for conflicts, first against the jobs we shall
         * create */
        if ((other = hashmap_get(m->jobs_to_add, name))) {

                if (other->type != type)
                        return -EEXIST;

        } else if (name->meta.job) {

                if (name->meta.job->type != type) {

                        if (mode == JOB_FAIL)
                                return -EEXIST;

                        if ((r = set_put(m->jobs_to_remove, name->meta.job)) < 0)
                                return r;
                }
        }

        if (!(ret = job_new(m, type, name)))
                return -ENOMEM;

        if ((r = hashmap_put(m->jobs_to_add, name, ret)) < 0)
                goto fail;

        if (type == JOB_START || type == JOB_VERIFY_STARTED || type == JOB_RESTART_FINISH) {
                SET_FOREACH(dep, ret->name->meta.dependencies[NAME_REQUIRES], state)
                        if ((r = manager_add_job(m, type, dep, mode, NULL)) < 0)
                                goto fail;
                SET_FOREACH(dep, ret->name->meta.dependencies[NAME_SOFT_REQUIRES], state)
                        if ((r = manager_add_job(m, type, dep, JOB_FAIL, NULL)) < 0)
                                goto fail;
                SET_FOREACH(dep, ret->name->meta.dependencies[NAME_WANTS], state)
                        if ((r = manager_add_job(m, type, dep, JOB_FAIL, NULL)) < 0)
                                goto fail;
                SET_FOREACH(dep, ret->name->meta.dependencies[NAME_REQUISITE], state)
                        if ((r = manager_add_job(m, JOB_VERIFY_STARTED, dep, mode, NULL)) < 0)
                                goto fail;
                SET_FOREACH(dep, ret->name->meta.dependencies[NAME_SOFT_REQUISITE], state)
                        if ((r = manager_add_job(m, JOB_VERIFY_STARTED, dep, JOB_FAIL, NULL)) < 0)
                                goto fail;
                SET_FOREACH(dep, ret->name->meta.dependencies[NAME_CONFLICTS], state)
                        if ((r = manager_add_job(m, type, dep, mode, NULL)) < 0)
                                goto fail;

        } else if (type == JOB_STOP || type == JOB_RESTART || type == JOB_TRY_RESTART) {

                SET_FOREACH(dep, ret->name->meta.dependencies[NAME_REQUIRED_BY], state)
                        if ((r = manager_add_job(m, type, dep, mode, NULL)) < 0)
                                goto fail;
        }

        if (_ret)
                *_ret = ret;

        return 0;

fail:
        job_free(ret);

        return r;
}


Job *manager_get_job(Manager *m, uint32_t id) {
        assert(m);

        return hashmap_get(m->jobs, UINT32_TO_PTR(id));
}

Name *manager_get_name(Manager *m, const char *name) {
        assert(m);
        assert(name);

        return hashmap_get(m->names, name);
}

static int verify_type(Name *name) {
        char *n;
        void *state;

        assert(name);

        /* Checks that all aliases of this name have the same and valid type */

        SET_FOREACH(n, name->meta.names, state) {
                NameType t;

                if ((t = name_type_from_string(n)) == _NAME_TYPE_INVALID)
                        return -EINVAL;

                if (name->meta.type == _NAME_TYPE_INVALID) {
                        name->meta.type = t;
                        continue;
                }

                if (name->meta.type != t)
                        return -EINVAL;
        }

        if (name->meta.type == _NAME_TYPE_INVALID)
                return -EINVAL;

        return 0;
}

static int service_load_sysv(Service *s) {
        assert(s);

        /* Load service data from SysV init scripts, preferably with
         * LSB headers ... */

        return 0;
}

static int name_load_fstab(Name *n) {
        assert(n);
        assert(n->meta.type == NAME_MOUNT || n->meta.type == NAME_AUTOMOUNT);

        /* Load mount data from /etc/fstab */

        return 0;
}

static int snapshot_load(Snapshot *s) {
        assert(s);

        /* Load snapshots from disk */

        return 0;
}

static int name_load_dropin(Name *n) {
        assert(n);

        /* Load dependencies from drop-in directories */

        return 0;
}

static int load(Name *name) {
        int r;

        assert(name);

        if (name->meta.state != NAME_STUB)
                return 0;

        if ((r = verify_type(name)) < 0)
                return r;

        if (name->meta.type == NAME_SERVICE) {

                /* Load a .service file */
                if ((r = name_load_fragment(name)) == 0)
                        goto finish;

                /* Load a classic init script */
                if (r == -ENOENT)
                        if ((r = service_load_sysv(SERVICE(name))) == 0)
                                goto finish;

        } else if (name->meta.type == NAME_MOUNT ||
                   name->meta.type == NAME_AUTOMOUNT) {

                if ((r = name_load_fstab(name)) == 0)
                        goto finish;

        } else if (name->meta.type == NAME_SNAPSHOT) {

                if ((r = snapshot_load(SNAPSHOT(name))) == 0)
                        goto finish;

        } else {
                if ((r = name_load_fragment(name)) == 0)
                        goto finish;
        }

        name->meta.state = NAME_FAILED;
        return r;

finish:
        if ((r = name_load_dropin(name)) < 0)
                return r;

        name->meta.state = NAME_LOADED;
        return 0;
}

static int dispatch_load_queue(Manager *m) {
        Meta *meta;

        assert(m);

        /* Make sure we are not run recursively */
        if (m->dispatching_load_queue)
                return 0;

        m->dispatching_load_queue = true;

        /* Dispatches the load queue. Takes a name from the queue and
         * tries to load its data until the queue is empty */

        while ((meta = m->load_queue)) {
                load(NAME(meta));
                LIST_REMOVE(Meta, m->load_queue, meta);
        }

        m->dispatching_load_queue = false;

        return 0;
}

int manager_load_name(Manager *m, const char *name, Name **_ret) {
        Name *ret;
        NameType t;
        int r;
        char *n;

        assert(m);
        assert(name);
        assert(_ret);

        if (!name_is_valid(name))
                return -EINVAL;

        /* This will load the service information files, but not actually
         * start any services or anything */

        if ((ret = manager_get_name(m, name)))
                goto finish;

        if ((t = name_type_from_string(name)) == _NAME_TYPE_INVALID)
                return -EINVAL;

        if (!(ret = name_new(m)))
                return -ENOMEM;

        ret->meta.type = t;

        if (!(n = strdup(name))) {
                name_free(ret);
                return -ENOMEM;
        }

        if (set_put(ret->meta.names, n) < 0) {
                name_free(ret);
                free(n);
                return -ENOMEM;
        }

        if ((r = name_link(ret)) < 0) {
                name_free(ret);
                return r;
        }

        /* At this point the new entry is created and linked. However,
         * not loaded. Now load this entry and all its dependencies
         * recursively */

        dispatch_load_queue(m);

finish:

        *_ret = ret;
        return 0;
}
