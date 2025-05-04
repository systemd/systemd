/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "devlink-match.h"
#include "hashmap.h"
#include "log.h"
#include "macro-fundamental.h"
#include "string-util.h"
#include "strv.h"
#include "stat-util.h"
#include "constants.h"

#include "devlink.h"
#include "devlink-kind.h"
#include "devlink-key.h"
#include "devlink-reload.h"
#include "devlink-nested.h"
#include "devlink-dev.h"
#include "devlinkd-manager.h"

const DevlinkVTable * const devlink_vtable[_DEVLINK_KIND_MAX] = {
        [DEVLINK_KIND_RELOAD] = &devlink_reload_vtable,
        [DEVLINK_KIND_NESTED] = &devlink_nested_vtable,
        [DEVLINK_KIND_DEV] = &devlink_dev_vtable,
};

static Devlink *devlink_alloc(Manager *m, DevlinkKind kind) {
        Devlink *devlink;

        devlink = malloc0(_DEVLINK_VTABLE(kind)->object_size);
        if (!devlink)
                return NULL;

        *devlink = (Devlink) {
                .manager = m,
                .n_ref = 1,
        };

        devlink_key_init(&devlink->key, kind);

        if (DEVLINK_VTABLE(devlink)->init)
                DEVLINK_VTABLE(devlink)->init(devlink);

        return devlink;
}

static Devlink *devlink_free(Devlink *devlink) {
        assert(devlink);

        devlink->expected_removal_timeout_event_source = sd_event_source_disable_unref(devlink->expected_removal_timeout_event_source);

        if (devlink->in_hashmap) {
                hashmap_remove(devlink->manager->devlink_objs, &devlink->key);
                manager_kind_dec(devlink->manager, devlink->key.kind);
        }

        free(devlink->filename);
        strv_free(devlink->dropins);

        if (DEVLINK_VTABLE(devlink)->done)
                DEVLINK_VTABLE(devlink)->done(devlink);

        devlink_key_fini(&devlink->key);

        hashmap_free(devlink->stats_by_path);

        return mfree(devlink);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Devlink, devlink, devlink_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        devlink_hash_ops,
        DevlinkKey,
        devlink_key_hash_func,
        devlink_key_compare_func,
        Devlink,
        devlink_unref);

static int devlink_put(Manager *m, Devlink *devlink) {
        int r;

        r = hashmap_ensure_put(&m->devlink_objs, &devlink_hash_ops, &devlink->key, devlink);
        if (r == -ENOMEM) {
                return log_oom();
        } else if (r == -EEXIST && devlink->filename) {
                Devlink *existing = hashmap_get(m->devlink_objs, &devlink->key);

                assert(existing);
                if (!streq(devlink->filename, existing->filename))
                        log_devlink_warning_errno(devlink, r, "Object was already configured by file %s", existing->filename);
                return 0;
        } else if (r < 0) {
                log_devlink_error_errno(devlink, r, "Failed to put to hashmap");
                return r;
        }
        devlink->in_hashmap = true;
        manager_kind_inc(m, devlink->key.kind);
        return 0;
}

static Devlink *devlink_create(Manager *m, DevlinkKey *key) {
        _cleanup_(devlink_unrefp) Devlink *devlink;
        int r;

        devlink = devlink_alloc(m, key->kind);
        if (!devlink) {
                (void) log_oom();
                return NULL;
        }
        r = devlink_key_duplicate(&devlink->key, key);
        if (r < 0) {
                (void) log_oom();
                return NULL;
        }
        r = devlink_put(m, devlink);
        if (r < 0) {
                assert(r != -EEXIST);
                return NULL;
        }

        return TAKE_PTR(devlink);
}

Devlink *devlink_get_may_create(Manager *m, DevlinkKey *key) {
        Devlink *devlink = hashmap_get(m->devlink_objs, key);

        if (!devlink && _DEVLINK_VTABLE(key->kind)->alloc_on_demand)
                devlink = devlink_create(m, key);

        return devlink;
}

Devlink *devlink_get_may_create_filtered(Manager *m, DevlinkKey *key, DevlinkMatchSet matchset) {
        Devlink *devlink;

        /* Check if the current matchset is subset of the one in te key. */
        if ((matchset & key->matchset) != matchset)
                return NULL;
        /* For the hashmap lookup, the matchset needs to be set to the filter. */
        SWAP_TWO(key->matchset, matchset);
        devlink = devlink_get_may_create(m, key);
        SWAP_TWO(key->matchset, matchset);
        return devlink;
}

Devlink *devlink_get(Manager *m, DevlinkKey *key) {
        return hashmap_get(m->devlink_objs, key);
}

static int devlink_matchset_select(Devlink *devlink) {
        DevlinkKey *key = &devlink->key;
        DevlinkMatchSet matchset;
        unsigned i = 0;

        while ((matchset = DEVLINK_VTABLE(devlink)->matchsets[i++])) {
                DevlinkMatchBit first_extra_bit = 0;
                DevlinkMatchCheckResult result = devlink_match_check(&key->match, matchset, &first_extra_bit);

                if (result == DEVLINK_MATCH_CHECK_RESULT_MATCH) {
                        devlink_key_matchset_set(key, matchset);
                        return 0;
                } else if (result == DEVLINK_MATCH_CHECK_RESULT_EXTRA_MATCH) {
                        log_warning("Extra key \"%s\" in \"Match\" section configured in %s. Ignoring",
                                    devlink_match_bit_to_string(first_extra_bit), devlink->filename);
                        return -ENOENT;
                }
        }
        log_warning("None or insufficient keys in \"Match\" section configured in %s. Ignoring", devlink->filename);
        return -ENOENT;
}

#define DEVLINK_DIRS ((const char* const*) CONF_PATHS_STRV("systemd/devlink"))

static int devlink_load_one(Manager *m, const char *filename, Devlink **ret) {
        _cleanup_(devlink_unrefp) Devlink *devlink = NULL;
        DevlinkKind kind = _DEVLINK_KIND_INVALID;
        const char *dropin_dirname;
        int r;

        assert(m);
        assert(filename);
        assert(ret);

        r = null_or_empty_path(filename);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;
        if (r > 0) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        log_debug("Parsing file: %s", filename);

        dropin_dirname = strjoina(basename(filename), ".d");
        r = config_parse_many(
                        STRV_MAKE_CONST(filename), DEVLINK_DIRS, dropin_dirname,
                        /* root = */ NULL,
                        DEVLINK_COMMON_SECTIONS,
                        config_item_perf_lookup, devlink_kind_gperf_lookup,
                        CONFIG_PARSE_RELAXED | CONFIG_PARSE_WARN, &kind,
                        NULL, NULL);
        if (r < 0)
                return r;

        if (kind == _DEVLINK_KIND_INVALID) {
                log_warning("Devlink has no Match.Kind= configured in %s. Ignoring", filename);
                return -EINVAL;
        }

        devlink = devlink_alloc(m, kind);
        if (!devlink)
                return log_oom();

        r = config_parse_many(
                        STRV_MAKE_CONST(filename), DEVLINK_DIRS, dropin_dirname,
                        /* root = */ NULL,
                        DEVLINK_VTABLE(devlink)->sections,
                        config_item_perf_lookup, devlink_gperf_lookup,
                        CONFIG_PARSE_WARN, devlink, &devlink->stats_by_path, &devlink->dropins);
        if (r < 0)
                return r;

        devlink->filename = strdup(filename);
        if (!devlink->filename)
                return log_oom();

        r = devlink_matchset_select(devlink);
        if (r < 0)
                return r;

        if (DEVLINK_VTABLE(devlink)->config_verify) {
                r = DEVLINK_VTABLE(devlink)->config_verify(devlink, filename);
                if (r < 0)
                        return r;
        }

        log_devlink_debug(devlink, "Loaded");

        *ret = TAKE_PTR(devlink);

        return 0;
}

static int devlink_config_load_internal(Manager *m, bool reload) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(m);

        r = conf_files_list_strv(&files, ".devlink", NULL, 0, DEVLINK_DIRS);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate devlink files: %m");

        STRV_FOREACH(f, files) {
                _cleanup_(devlink_unrefp) Devlink *devlink = NULL;

                r = devlink_load_one(m, *f, &devlink);
                if (r < 0) {
                        log_error_errno(r, "Failed to load %s, ignoring", *f);
                        continue;
                }

                if (reload) {
                        Devlink *old = devlink_get(m, &devlink->key);

                        if (!old) {
                                log_devlink_debug(devlink, "Found new .devlink file: %s", devlink->filename);
                        } else if (!stats_by_path_equal(devlink->stats_by_path, old->stats_by_path)) {
                                log_devlink_debug(devlink, "Found updated .devlink file: %s", devlink->filename);
                                devlink_unref(old);
                        } else {
                                log_devlink_debug(devlink, "Found unchanged .devlink file: %s", devlink->filename);
                                continue;
                        }
                }
                r = devlink_put(m, devlink);
                if (r < 0)
                        continue;
                TAKE_PTR(devlink);
        }

        return 0;
}

int devlink_config_load(Manager *m) {
        return devlink_config_load_internal(m, false);
}

int devlink_config_reload(Manager *m) {
        return devlink_config_load_internal(m, true);
}

void devlink_genl_process_message(sd_netlink_message *message,
                                  Manager *m, DevlinkKind kind,
                                  const DevlinkMonitorCommand *monitor_cmd) {
        const DevlinkVTable *vtable = _DEVLINK_VTABLE(kind);
        DevlinkMatchSet matchset;
        int r;

        if (!monitor_cmd->msg_process)
                return;

        DevlinkKey key = {};

        devlink_key_init(&key, kind);
        devlink_match_genl_read(message, m, &key.match, &key.matchset);

        Devlink *devlink = NULL;
        unsigned i = 0;
        while ((matchset = vtable->matchsets[i++])) {
                devlink = devlink_get_may_create_filtered(m, &key, matchset);
                if (devlink)
                        break;
        }
        if (devlink) {
                log_devlink_debug(devlink, "Matched object");
                r = monitor_cmd->msg_process(devlink, &key, message);
                if (r < 0)
                        log_debug_errno(r, "Failed to process netlink message, ignoring: %m");
                if (r == DEVLINK_MONITOR_COMMAND_RETVAL_DELETE)
                        devlink_unref(devlink);
        }

        devlink_key_fini(&key);
}

static int devlink_expected_removal_timeout_event_callback(sd_event_source *source, usec_t usec, void *userdata) {
        Devlink *devlink = ASSERT_PTR(userdata);

        assert(source == devlink->expected_removal_timeout_event_source);
        log_devlink_warning(devlink, "Expected removal did not happen within timeout");

        devlink_expected_removal_clear(devlink);

        return 0;
}

#define DEVLINK_EXPECTED_REMOVAL_TIMEOUT USEC_PER_SEC * 20

void devlink_expected_removal_set(Devlink *devlink) {
        int r;

        if (devlink->expected_removal_timeout_event_source) {
                r = sd_event_source_set_time_relative(
                                devlink->expected_removal_timeout_event_source,
                                DEVLINK_EXPECTED_REMOVAL_TIMEOUT);
                if (r < 0)
                        goto errout;

                r = sd_event_source_set_enabled(
                                devlink->expected_removal_timeout_event_source,
                                SD_EVENT_ONESHOT);
                if (r < 0)
                        goto errout;
        }
        r = sd_event_add_time_relative(
                        devlink->manager->event,
                        &devlink->expected_removal_timeout_event_source,
                        CLOCK_MONOTONIC, DEVLINK_EXPECTED_REMOVAL_TIMEOUT, 0,
                        devlink_expected_removal_timeout_event_callback,
                        devlink);
        if (r < 0)
                goto errout;

        (void) sd_event_source_set_description(
                        devlink->expected_removal_timeout_event_source,
                        "devlink-expected-removal-timeout");

        devlink->expected_removal = true;

        return;

errout:
       log_devlink_warning(devlink, "Failed to schedule expected removal timeout");
}

void devlink_expected_removal_clear(Devlink *devlink) {
        devlink->expected_removal_timeout_event_source = sd_event_source_disable_unref(devlink->expected_removal_timeout_event_source);
        devlink->expected_removal = false;
}