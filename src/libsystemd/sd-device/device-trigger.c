/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdbool.h>
#include <sys/utsname.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "device-enumerator-private.h"
#include "device-private.h"
#include "device-trigger-private.h"
#include "device-util.h"
#include "fileio.h"
#include "id128-util.h"
#include "hashmap.h"
#include "set.h"
#include "string-util.h"
#include "time-util.h"

#define EXT_SYNTH_MIN_KERNEL_VERSION "4.13"

#define SYNTH_UUID_KEY       "SYNTH_UUID"
#define SOURCE_KEY           "SOURCE"
#define DEFAULT_SOURCE_VALUE "SD"

struct sd_device_trigger {
        unsigned n_ref;

        sd_device **devices;
        size_t n_devices, n_allocated;

        const char *action;
        char uuid[SD_ID128_UUID_STRING_MAX];
        const char *source;
        Hashmap *properties;

        Set *settle_set;

        sd_device_trigger_callback_t pre_trigger_cb;
        void *pre_trigger_cb_userdata;
        sd_device_trigger_callback_t settle_cb;
        void *settle_cb_userdata;

        bool extended:1;
        bool executing:1;
};

static int device_trigger_ensure_uuid_set(sd_device_trigger *trigger) {
        sd_id128_t id;
        int r;

        if (!isempty(trigger->uuid))
                return 0;

        r = sd_id128_randomize(&id);
        if (r < 0)
                return log_debug_errno(r, "sd-device-trigger: Failed to generate random UUID: %m");

        id128_to_uuid_string(id, trigger->uuid);
        return 0;
}

static inline void device_trigger_discard_uuid(sd_device_trigger *trigger) {
        trigger->uuid[0] = '\0';
}

_public_ int sd_device_trigger_new(sd_device_trigger **ret) {
        _cleanup_(sd_device_trigger_unrefp) sd_device_trigger *trigger = NULL;
        struct utsname u;

        assert(ret);
        assert_se(uname(&u) >= 0);

        trigger = new(sd_device_trigger, 1);
        if (!trigger)
                return -ENOMEM;

        *trigger = (sd_device_trigger) {
                .n_ref = 1,
                .action = device_action_to_string(DEVICE_ACTION_CHANGE),
                .source = DEFAULT_SOURCE_VALUE,
                .extended = str_verscmp(u.release, EXT_SYNTH_MIN_KERNEL_VERSION) >= 0,
        };

        device_trigger_discard_uuid(trigger);

        *ret = TAKE_PTR(trigger);

        return 0;
}

static sd_device_trigger *device_trigger_free(sd_device_trigger *trigger) {
        size_t i;

        for (i = 0; i < trigger->n_devices; i++)
                sd_device_unref(trigger->devices[i]);

        free(trigger->devices);
        hashmap_free_free_free(trigger->properties);

        return mfree(trigger);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_device_trigger, sd_device_trigger, device_trigger_free);

_public_ int sd_device_trigger_set_action(sd_device_trigger *trigger, const char *action) {
        DeviceAction device_action;

        assert_return(trigger, -EINVAL);

        if (trigger->executing)
                return -EPERM;

        device_action = device_action_from_string(action);
        if (device_action < 0)
                return -EINVAL;

        trigger->action = action;

        return 0;
}

_public_ const char *sd_device_trigger_get_action(sd_device_trigger *trigger) {
        assert_return_errno(trigger, NULL, EINVAL);

        return trigger->action;
}

_public_ const char *sd_device_trigger_get_uuid(sd_device_trigger *trigger) {
        int r;

        assert_return(trigger, NULL);

        r = device_trigger_ensure_uuid_set(trigger);
        if (r < 0)
                return NULL;

        return trigger->uuid;
}

_public_ int sd_device_trigger_set_source(sd_device_trigger *trigger, const char *source) {
        assert_return(trigger, -EINVAL);

        if (trigger->executing)
                return -EPERM;

        if (!in_charset(source, ALPHANUMERICAL))
                return -EINVAL;

        trigger->source = source;

        return 0;
}

_public_ const char *sd_device_trigger_get_source(sd_device_trigger *trigger) {
        assert_return_errno(trigger, NULL, EINVAL);

        return trigger->source;
}

_public_ int sd_device_trigger_add_device(sd_device_trigger *trigger, sd_device *device) {
        assert_return(trigger, -EINVAL);
        assert_return(device, -EINVAL);

        if (trigger->executing)
                return -EPERM;

        if (!GREEDY_REALLOC(trigger->devices, trigger->n_allocated, trigger->n_devices + 1))
               return -ENOMEM;

        trigger->devices[trigger->n_devices++] = sd_device_ref(device);

        return 0;
}

_public_ int sd_device_trigger_add_enumerator(sd_device_trigger *trigger, sd_device_enumerator *enumerator) {
        sd_device **devices;
        size_t i, n_devices;

        assert_return(trigger, -EINVAL);
        assert_return(trigger, -EINVAL);

        if (trigger->executing)
                return -EPERM;

        devices = device_enumerator_get_devices(enumerator, &n_devices);

        if (!devices || !n_devices)
                return 0;

        if (!GREEDY_REALLOC(trigger->devices, trigger->n_allocated, trigger->n_devices + n_devices))
                return -ENOMEM;

        for (i = 0; i < n_devices; i++)
                trigger->devices[trigger->n_devices++] = sd_device_ref(devices[i]);

        return 0;
}

sd_device **device_trigger_get_devices(sd_device_trigger *trigger, size_t *ret_n_devices) {
        assert_return(trigger, NULL);
        assert_return(ret_n_devices, NULL);

        *ret_n_devices = trigger->n_devices;
        return trigger->devices;
}

_public_ int sd_device_trigger_add_property(sd_device_trigger *trigger, const char *_key, const char *_value) {
        _cleanup_free_ char *key = NULL;
        _cleanup_free_ char *value = NULL;
        int r;

        assert_return(trigger, -EINVAL);
        assert_return(_key, -EINVAL);
        assert_return(_value, -EINVAL);

        if (trigger->executing)
                return -EPERM;

        if (!in_charset(_key, ALPHANUMERICAL) ||
            !in_charset(_value, ALPHANUMERICAL))
                return log_debug_errno(-EINVAL, "sd-device-trigger: Incorrect property '%s=%s': "
                                                "non-alphanumeric characters used", _key, _value);

        if (streq(_key, SOURCE_KEY))
                return log_debug_errno(-EINVAL, "sd-device-trigger: Incorrect property '%s=%s': "
                                                 "key reserved for internal use", _key, _value);

        r = hashmap_ensure_allocated(&trigger->properties, NULL);
        if (r < 0)
                return r;

        key = strdup(_key);
        if (!key)
                return -ENOMEM;

        value = strdup(_value);
        if (!value)
                return -ENOMEM;

        r = hashmap_put(trigger->properties, key, value);
        if (r < 0)
                return r;

        key = NULL;
        value = NULL;

        return 0;
}

Hashmap *device_trigger_get_properties(sd_device_trigger *trigger) {
        assert_return_errno(trigger, NULL, EINVAL);

        return trigger->properties;
}

static char *device_trigger_get_full_action(sd_device_trigger *trigger) {
        const char *key;
        const char *value;
        char *full_action;
        Iterator i;

        if (!trigger->extended)
                return strdup(trigger->action);

        full_action = strjoin(trigger->action, " ", trigger->uuid, " " SOURCE_KEY "=", trigger->source);
        if (!full_action)
                return NULL;

        if (trigger->properties) {
                HASHMAP_FOREACH_KEY(value, key, trigger->properties, i) {
                        _cleanup_free_ char *s = full_action;

                        full_action = strjoin(s, " ", key, "=", value);
                        if (!full_action)
                                return NULL;
                }
        }

        return full_action;
}

static void device_trigger_cleanup_executing(sd_device_trigger **trigger) {
        (*trigger)->executing = false;
}

static int device_trigger_execute_common(sd_device_trigger *trigger) {
        _cleanup_(device_trigger_cleanup_executing) sd_device_trigger *t = trigger;
        _cleanup_free_ char *full_action = NULL;
        const char *syspath;
        size_t i;
        int r, ret = 0;

        t->executing = true;

        full_action = device_trigger_get_full_action(trigger);
        if (!full_action)
                return -ENOMEM;

        log_debug("sd-device-trigger: %s: Executing trigger on %zu devices%s",
                  trigger->uuid, trigger->n_devices, trigger->settle_set ? " with settle" : "");

        for (i = 0; i < trigger->n_devices; i++) {
                _cleanup_free_ char *sys_uevent_path = NULL;
                _cleanup_free_ char *settle_key = NULL;

                r = sd_device_get_syspath(trigger->devices[i], &syspath);
                if (r < 0)
                        return r;

                sys_uevent_path = strjoin(syspath, "/uevent");
                if (!sys_uevent_path)
                        return -ENOMEM;

                if (trigger->pre_trigger_cb)
                        if (trigger->pre_trigger_cb(trigger, trigger->devices[i], trigger->pre_trigger_cb_userdata))
                                continue;

                r = write_string_file(sys_uevent_path, full_action, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0) {
                        log_debug_errno(r, "sd-device-trigger: %s: %s: %zu/%zu: Failed to write '%s' to '%s': %m",
                                        trigger->uuid, syspath, i+1, trigger->n_devices, full_action, sys_uevent_path);

                        if (ret == 0 && !IN_SET(r, -ENOENT, -EACCES, -ENODEV))
                             ret = r;
                        continue;
                }

                log_debug("sd-device-trigger: %s: %s: %zu/%zu: Triggered",
                          trigger->uuid, syspath, i+1, trigger->n_devices);

                if (trigger->settle_set) {
                        settle_key = strjoin(trigger->uuid, syspath);
                        if (!settle_key)
                                return -ENOMEM;

                        r = set_put_strdup(trigger->settle_set, settle_key);
                        if (r < 0)
                                return r;
                }
        }

        return ret;
}

int sd_device_trigger_set_pre_trigger_callback(sd_device_trigger *trigger, sd_device_trigger_callback_t cb, void *userdata) {
        trigger->pre_trigger_cb = cb;
        trigger->pre_trigger_cb_userdata = userdata;

        return 0;
}

int sd_device_trigger_set_settle_callback(sd_device_trigger *trigger, sd_device_trigger_callback_t cb, void *userdata) {
        trigger->settle_cb = cb;
        trigger->settle_cb_userdata = userdata;

        return 0;
}

_public_ int sd_device_trigger_execute(sd_device_trigger *trigger) {
        int r;

        assert_return(trigger, -EINVAL);

        if (trigger->executing)
                return -EPERM;

        r = device_trigger_ensure_uuid_set(trigger);
        if (r < 0)
                return r;

        r = device_trigger_execute_common(trigger);

        device_trigger_discard_uuid(trigger);

        return r;
}

static int device_trigger_monitor_handler(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        sd_device_trigger *trigger = userdata;
        const char *syspath;
        const char *uuid;
        _cleanup_free_ char *settle_key = NULL;
        char *found_key;
        int r;

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        if (trigger->extended) {
                r = sd_device_get_property_value(device, SYNTH_UUID_KEY, &uuid);
                if (r < 0) {
                       if (r == -ENOENT)
                               /* ignore uevents which are not synthetic */
                               return 0;
                       return r;
                }

                if (!streq(uuid, trigger->uuid))
                        /* we are interested in synthetic uevents with specific UUID only */
                        return 0;
        }

        settle_key = strjoin(trigger->uuid, syspath);
        if (!settle_key)
                return -ENOMEM;

        found_key = set_remove(trigger->settle_set, settle_key);
        if (!found_key)
                return 0;

        free(found_key);

        log_debug("sd-device-trigger: %s: %s: Settled", trigger->uuid, syspath);

         if (trigger->settle_cb)
                 (void) trigger->settle_cb(trigger, device, trigger->settle_cb_userdata);

        if (set_isempty(trigger->settle_set))
                return sd_event_exit(sd_device_monitor_get_event(monitor), 0);

        return 0;
}

static int device_trigger_timeout_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_device_trigger *trigger = userdata;

        log_debug("sd-device-trigger: %s: Timed out", trigger->uuid);

        return sd_event_exit(sd_event_source_get_event(s), -ETIMEDOUT);
}

_public_ int sd_device_trigger_execute_with_settle(sd_device_trigger *trigger, unsigned int timeout_sec) {
        _cleanup_set_free_free_ Set *settle_set = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *timeout = NULL;
        uint64_t now_usec;
        int r;

        assert_return(trigger, -ENOMEM);

        if (trigger->executing)
                return -EPERM;

        trigger->settle_set = settle_set = set_new(&string_hash_ops);
        if (!settle_set)
                return -ENOMEM;

        r = sd_event_default(&event);
        if (r < 0)
                return r;

        r = sd_device_monitor_new(&monitor);
        if (r < 0)
                return r;

        r = sd_device_monitor_attach_event(monitor, event);
        if (r < 0)
                return r;

        if (timeout_sec > 0) {
                r = sd_event_now(event, CLOCK_MONOTONIC, &now_usec);
                if (r < 0)
                        return r;

                r = sd_event_add_time(event, &timeout, CLOCK_MONOTONIC,
                                      now_usec + timeout_sec * USEC_PER_SEC, USEC_PER_SEC,
                                      device_trigger_timeout_handler, trigger);
                if (r < 0)
                        return r;
        }

        r = sd_device_monitor_start(monitor, device_trigger_monitor_handler, trigger);
        if (r < 0)
                return r;

        r = device_trigger_ensure_uuid_set(trigger);
        if (r < 0)
                return r;

        r = device_trigger_execute_common(trigger);

        if (r == 0 && !set_isempty(trigger->settle_set))
                r = sd_event_loop(event);

        device_trigger_discard_uuid(trigger);

        if (r < 0)
                return r;

        return 0;
}
