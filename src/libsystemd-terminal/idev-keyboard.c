/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 David Herrmann <dh.herrmann@gmail.com>

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

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include <xkbcommon/xkbcommon.h>
#include "bus-util.h"
#include "hashmap.h"
#include "idev.h"
#include "idev-internal.h"
#include "macro.h"
#include "util.h"

typedef struct kbdmap kbdmap;
typedef struct kbdctx kbdctx;
typedef struct idev_keyboard idev_keyboard;

struct kbdmap {
        unsigned long ref;
        struct xkb_keymap *xkb_keymap;
        xkb_mod_index_t modmap[IDEV_KBDMOD_CNT];
        xkb_led_index_t ledmap[IDEV_KBDLED_CNT];
};

struct kbdctx {
        unsigned long ref;
        idev_context *context;
        struct xkb_context *xkb_context;
        struct kbdmap *kbdmap;

        sd_bus_slot *slot_locale_props_changed;
        sd_bus_slot *slot_locale_get_all;

        char *locale_x11_model;
        char *locale_x11_layout;
        char *locale_x11_variant;
        char *locale_x11_options;
        char *last_x11_model;
        char *last_x11_layout;
        char *last_x11_variant;
        char *last_x11_options;
};

struct idev_keyboard {
        idev_device device;
        kbdctx *kbdctx;
        kbdmap *kbdmap;

        struct xkb_state *xkb_state;

        usec_t repeat_delay;
        usec_t repeat_rate;
        sd_event_source *repeat_timer;

        uint32_t n_syms;
        idev_data evdata;
        idev_data repdata;

        bool repeating : 1;
};

#define keyboard_from_device(_d) container_of((_d), idev_keyboard, device)

#define KBDCTX_KEY "keyboard.context"           /* hashmap key for global kbdctx */
#define KBDXKB_SHIFT (8)                        /* xkb shifts evdev key-codes by 8 */
#define KBDKEY_UP (0)                           /* KEY UP event value */
#define KBDKEY_DOWN (1)                         /* KEY DOWN event value */
#define KBDKEY_REPEAT (2)                       /* KEY REPEAT event value */

static const idev_device_vtable keyboard_vtable;

static int keyboard_update_kbdmap(idev_keyboard *k);

/*
 * Keyboard Keymaps
 */

static const char * const kbdmap_modmap[IDEV_KBDMOD_CNT] = {
        [IDEV_KBDMOD_IDX_SHIFT]                 = XKB_MOD_NAME_SHIFT,
        [IDEV_KBDMOD_IDX_CTRL]                  = XKB_MOD_NAME_CTRL,
        [IDEV_KBDMOD_IDX_ALT]                   = XKB_MOD_NAME_ALT,
        [IDEV_KBDMOD_IDX_LINUX]                 = XKB_MOD_NAME_LOGO,
        [IDEV_KBDMOD_IDX_CAPS]                  = XKB_MOD_NAME_CAPS,
};

static const char * const kbdmap_ledmap[IDEV_KBDLED_CNT] = {
        [IDEV_KBDLED_IDX_NUM]                   = XKB_LED_NAME_NUM,
        [IDEV_KBDLED_IDX_CAPS]                  = XKB_LED_NAME_CAPS,
        [IDEV_KBDLED_IDX_SCROLL]                = XKB_LED_NAME_SCROLL,
};

static kbdmap *kbdmap_ref(kbdmap *km) {
        assert_return(km, NULL);
        assert_return(km->ref > 0, NULL);

        ++km->ref;
        return km;
}

static kbdmap *kbdmap_unref(kbdmap *km) {
        if (!km)
                return NULL;

        assert_return(km->ref > 0, NULL);

        if (--km->ref > 0)
                return NULL;

        xkb_keymap_unref(km->xkb_keymap);
        free(km);

        return 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(kbdmap*, kbdmap_unref);

static int kbdmap_new_from_names(kbdmap **out,
                                 kbdctx *kc,
                                 const char *model,
                                 const char *layout,
                                 const char *variant,
                                 const char *options) {
        _cleanup_(kbdmap_unrefp) kbdmap *km = NULL;
        struct xkb_rule_names rmlvo = { };
        unsigned int i;

        assert_return(out, -EINVAL);

        km = new0(kbdmap, 1);
        if (!km)
                return -ENOMEM;

        km->ref = 1;

        rmlvo.rules = "evdev";
        rmlvo.model = model;
        rmlvo.layout = layout;
        rmlvo.variant = variant;
        rmlvo.options = options;

        errno = 0;
        km->xkb_keymap = xkb_keymap_new_from_names(kc->xkb_context, &rmlvo, 0);
        if (!km->xkb_keymap)
                return errno > 0 ? -errno : -EFAULT;

        for (i = 0; i < IDEV_KBDMOD_CNT; ++i) {
                const char *t = kbdmap_modmap[i];

                if (t)
                        km->modmap[i] = xkb_keymap_mod_get_index(km->xkb_keymap, t);
                else
                        km->modmap[i] = XKB_MOD_INVALID;
        }

        for (i = 0; i < IDEV_KBDLED_CNT; ++i) {
                const char *t = kbdmap_ledmap[i];

                if (t)
                        km->ledmap[i] = xkb_keymap_led_get_index(km->xkb_keymap, t);
                else
                        km->ledmap[i] = XKB_LED_INVALID;
        }

        *out = km;
        km = NULL;
        return 0;
}

/*
 * Keyboard Context
 */

static void move_str(char **dest, char **src) {
        free(*dest);
        *dest = *src;
        *src = NULL;
}

static int kbdctx_refresh_keymap(kbdctx *kc) {
        idev_session *s;
        idev_device *d;
        Iterator i, j;
        kbdmap *km;
        int r;

        if (kc->kbdmap &&
            streq_ptr(kc->locale_x11_model, kc->last_x11_model) &&
            streq_ptr(kc->locale_x11_layout, kc->last_x11_layout) &&
            streq_ptr(kc->locale_x11_variant, kc->last_x11_variant) &&
            streq_ptr(kc->locale_x11_options, kc->last_x11_options))
                return 0 ;

        move_str(&kc->last_x11_model, &kc->locale_x11_model);
        move_str(&kc->last_x11_layout, &kc->locale_x11_layout);
        move_str(&kc->last_x11_variant, &kc->locale_x11_variant);
        move_str(&kc->last_x11_options, &kc->locale_x11_options);

        log_debug("idev-keyboard: new default keymap: [%s / %s / %s / %s]",
                  kc->last_x11_model, kc->last_x11_layout, kc->last_x11_variant, kc->last_x11_options);

        /* TODO: add a fallback keymap that's compiled-in */
        r = kbdmap_new_from_names(&km, kc, kc->last_x11_model, kc->last_x11_layout,
                                  kc->last_x11_variant, kc->last_x11_options);
        if (r < 0) {
                log_debug("idev-keyboard: cannot create keymap from locale1: %s",
                          strerror(-r));
                return r;
        }

        kbdmap_unref(kc->kbdmap);
        kc->kbdmap = km;

        HASHMAP_FOREACH(s, kc->context->session_map, i)
                HASHMAP_FOREACH(d, s->device_map, j)
                        if (idev_is_keyboard(d))
                                keyboard_update_kbdmap(keyboard_from_device(d));

        return 0;
}

static const struct bus_properties_map kbdctx_locale_map[] = {
        { "X11Model",   "s",    NULL, offsetof(kbdctx, locale_x11_model) },
        { "X11Layout",  "s",    NULL, offsetof(kbdctx, locale_x11_layout) },
        { "X11Variant", "s",    NULL, offsetof(kbdctx, locale_x11_variant) },
        { "X11Options", "s",    NULL, offsetof(kbdctx, locale_x11_options) },
};

static int kbdctx_locale_get_all_fn(sd_bus *bus,
                                    sd_bus_message *m,
                                    void *userdata,
                                    sd_bus_error *ret_err) {
        kbdctx *kc = userdata;
        int r;

        kc->slot_locale_get_all = sd_bus_slot_unref(kc->slot_locale_get_all);

        if (sd_bus_message_is_method_error(m, NULL)) {
                const sd_bus_error *error = sd_bus_message_get_error(m);

                log_debug("idev-keyboard: GetAll() on locale1 failed: %s: %s",
                          error->name, error->message);
                return 0;
        }

        r = bus_message_map_all_properties(bus, m, kbdctx_locale_map, kc);
        if (r < 0) {
                log_debug("idev-keyboard: erroneous GetAll() reply from locale1");
                return 0;
        }

        kbdctx_refresh_keymap(kc);
        return 0;
}

static int kbdctx_query_locale(kbdctx *kc) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        kc->slot_locale_get_all = sd_bus_slot_unref(kc->slot_locale_get_all);

        r = sd_bus_message_new_method_call(kc->context->sysbus,
                                           &m,
                                           "org.freedesktop.locale1",
                                           "/org/freedesktop/locale1",
                                           "org.freedesktop.DBus.Properties",
                                           "GetAll");
        if (r < 0)
                goto error;

        r = sd_bus_message_append(m, "s", "org.freedesktop.locale1");
        if (r < 0)
                goto error;

        r = sd_bus_call_async(kc->context->sysbus,
                              &kc->slot_locale_get_all,
                              m,
                              kbdctx_locale_get_all_fn,
                              kc,
                              0);
        if (r < 0)
                goto error;

        return 0;

error:
        log_debug("idev-keyboard: cannot send GetAll to locale1: %s", strerror(-r));
        return r;
}

static int kbdctx_locale_props_changed_fn(sd_bus *bus,
                                          sd_bus_message *signal,
                                          void *userdata,
                                          sd_bus_error *ret_err) {
        kbdctx *kc = userdata;
        int r;

        kc->slot_locale_get_all = sd_bus_slot_unref(kc->slot_locale_get_all);

        /* skip interface name */
        r = sd_bus_message_skip(signal, "s");
        if (r < 0)
                goto error;

        r = bus_message_map_properties_changed(bus, signal, kbdctx_locale_map, kc);
        if (r < 0)
                goto error;

        if (r > 0) {
                r = kbdctx_query_locale(kc);
                if (r < 0)
                        return r;
        }

        kbdctx_refresh_keymap(kc);
        return 0;

error:
        log_debug("idev-keyboard: cannot handle PropertiesChanged from locale1: %s", strerror(-r));
        return r;
}

static int kbdctx_setup_bus(kbdctx *kc) {
        int r;

        r = sd_bus_add_match(kc->context->sysbus,
                             &kc->slot_locale_props_changed,
                             "type='signal',"
                             "sender='org.freedesktop.locale1',"
                             "interface='org.freedesktop.DBus.Properties',"
                             "member='PropertiesChanged',"
                             "path='/org/freedesktop/locale1'",
                             kbdctx_locale_props_changed_fn,
                             kc);
        if (r < 0) {
                log_debug("idev-keyboard: cannot setup locale1 link: %s", strerror(-r));
                return r;
        }

        return kbdctx_query_locale(kc);
}

static kbdctx *kbdctx_ref(kbdctx *kc) {
        assert_return(kc, NULL);
        assert_return(kc->ref > 0, NULL);

        ++kc->ref;
        return kc;
}

static kbdctx *kbdctx_unref(kbdctx *kc) {
        if (!kc)
                return NULL;

        assert_return(kc->ref > 0, NULL);

        if (--kc->ref > 0)
                return NULL;

        free(kc->last_x11_options);
        free(kc->last_x11_variant);
        free(kc->last_x11_layout);
        free(kc->last_x11_model);
        free(kc->locale_x11_options);
        free(kc->locale_x11_variant);
        free(kc->locale_x11_layout);
        free(kc->locale_x11_model);
        kc->slot_locale_get_all = sd_bus_slot_unref(kc->slot_locale_get_all);
        kc->slot_locale_props_changed = sd_bus_slot_unref(kc->slot_locale_props_changed);
        kc->kbdmap = kbdmap_unref(kc->kbdmap);
        xkb_context_unref(kc->xkb_context);
        hashmap_remove_value(kc->context->data_map, KBDCTX_KEY, kc);
        free(kc);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(kbdctx*, kbdctx_unref);

static int kbdctx_new(kbdctx **out, idev_context *c) {
        _cleanup_(kbdctx_unrefp) kbdctx *kc = NULL;
        int r;

        assert_return(out, -EINVAL);
        assert_return(c, -EINVAL);

        kc = new0(kbdctx, 1);
        if (!kc)
                return -ENOMEM;

        kc->ref = 1;
        kc->context = c;

        errno = 0;
        kc->xkb_context = xkb_context_new(0);
        if (!kc->xkb_context)
                return errno > 0 ? -errno : -EFAULT;

        r = kbdctx_refresh_keymap(kc);
        if (r < 0)
                return r;

        if (c->sysbus) {
                r = kbdctx_setup_bus(kc);
                if (r < 0)
                        return r;
        }

        r = hashmap_put(c->data_map, KBDCTX_KEY, kc);
        if (r < 0)
                return r;

        *out = kc;
        kc = NULL;
        return 0;
}

static int get_kbdctx(idev_context *c, kbdctx **out) {
        kbdctx *kc;

        assert_return(c, -EINVAL);
        assert_return(out, -EINVAL);

        kc = hashmap_get(c->data_map, KBDCTX_KEY);
        if (kc) {
                *out = kbdctx_ref(kc);
                return 0;
        }

        return kbdctx_new(out, c);
}

/*
 * Keyboard Devices
 */

bool idev_is_keyboard(idev_device *d) {
        return d && d->vtable == &keyboard_vtable;
}

idev_device *idev_find_keyboard(idev_session *s, const char *name) {
        char *kname;

        assert_return(s, NULL);
        assert_return(name, NULL);

        kname = strappenda("keyboard/", name);
        return hashmap_get(s->device_map, kname);
}

static int keyboard_raise_data(idev_keyboard *k, idev_data *data) {
        idev_device *d = &k->device;
        int r;

        r = idev_session_raise_device_data(d->session, d, data);
        if (r < 0)
                log_debug("idev-keyboard: %s/%s: error while raising data event: %s",
                          d->session->name, d->name, strerror(-r));

        return r;
}

static void keyboard_arm(idev_keyboard *k, usec_t usecs) {
        int r;

        if (usecs != 0) {
                usecs += now(CLOCK_MONOTONIC);
                r = sd_event_source_set_time(k->repeat_timer, usecs);
                if (r >= 0)
                        sd_event_source_set_enabled(k->repeat_timer, SD_EVENT_ONESHOT);
        } else {
                sd_event_source_set_enabled(k->repeat_timer, SD_EVENT_OFF);
        }
}

static int keyboard_repeat_timer_fn(sd_event_source *source, uint64_t usec, void *userdata) {
        idev_keyboard *k = userdata;

        keyboard_arm(k, k->repeat_rate);
        return keyboard_raise_data(k, &k->repdata);
}

int idev_keyboard_new(idev_device **out, idev_session *s, const char *name) {
        _cleanup_(idev_device_freep) idev_device *d = NULL;
        idev_keyboard *k;
        char *kname;
        int r;

        assert_return(out, -EINVAL);
        assert_return(s, -EINVAL);
        assert_return(name, -EINVAL);

        k = new0(idev_keyboard, 1);
        if (!k)
                return -ENOMEM;

        d = &k->device;
        k->device = IDEV_DEVICE_INIT(&keyboard_vtable, s);
        k->repeat_delay = 250 * USEC_PER_MSEC;
        k->repeat_rate = 30 * USEC_PER_MSEC;

        /* TODO: add key-repeat configuration */

        r = get_kbdctx(s->context, &k->kbdctx);
        if (r < 0)
                return r;

        r = keyboard_update_kbdmap(k);
        if (r < 0)
                return r;

        r = sd_event_add_time(s->context->event,
                              &k->repeat_timer,
                              CLOCK_MONOTONIC,
                              0,
                              10 * USEC_PER_MSEC,
                              keyboard_repeat_timer_fn,
                              k);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(k->repeat_timer, SD_EVENT_OFF);
        if (r < 0)
                return r;

        kname = strappenda("keyboard/", name);
        r = idev_device_add(d, kname);
        if (r < 0)
                return r;

        if (out)
                *out = d;
        d = NULL;
        return 0;
}

static void keyboard_free(idev_device *d) {
        idev_keyboard *k = keyboard_from_device(d);

        xkb_state_unref(k->xkb_state);
        free(k->repdata.keyboard.codepoints);
        free(k->repdata.keyboard.keysyms);
        free(k->evdata.keyboard.codepoints);
        free(k->evdata.keyboard.keysyms);
        k->repeat_timer = sd_event_source_unref(k->repeat_timer);
        k->kbdmap = kbdmap_unref(k->kbdmap);
        k->kbdctx = kbdctx_unref(k->kbdctx);
        free(k);
}

static int8_t guess_ascii(struct xkb_state *state, uint32_t code, uint32_t n_syms, const uint32_t *syms) {
        xkb_layout_index_t n_lo, lo;
        xkb_level_index_t lv;
        struct xkb_keymap *keymap;
        const xkb_keysym_t *s;
        int num;

        if (n_syms == 1 && syms[0] < 128 && syms[0] > 0)
                return syms[0];

        keymap = xkb_state_get_keymap(state);
        n_lo = xkb_keymap_num_layouts_for_key(keymap, code + KBDXKB_SHIFT);

        for (lo = 0; lo < n_lo; ++lo) {
                lv = xkb_state_key_get_level(state, code + KBDXKB_SHIFT, lo);
                num = xkb_keymap_key_get_syms_by_level(keymap, code + KBDXKB_SHIFT, lo, lv, &s);
                if (num == 1 && s[0] < 128 && s[0] > 0)
                        return s[0];
        }

        return -1;
}

static int keyboard_fill(idev_keyboard *k,
                         idev_data *dst,
                         bool resync,
                         uint16_t code,
                         uint32_t value,
                         uint32_t n_syms,
                         const uint32_t *keysyms) {
        idev_data_keyboard *kev;
        uint32_t i;

        assert(dst == &k->evdata || dst == &k->repdata);

        if (n_syms > k->n_syms) {
                uint32_t *t;

                t = realloc(k->evdata.keyboard.keysyms, sizeof(*t) * n_syms);
                if (!t)
                        return -ENOMEM;
                k->evdata.keyboard.keysyms = t;

                t = realloc(k->evdata.keyboard.codepoints, sizeof(*t) * n_syms);
                if (!t)
                        return -ENOMEM;
                k->evdata.keyboard.codepoints = t;

                t = realloc(k->repdata.keyboard.keysyms, sizeof(*t) * n_syms);
                if (!t)
                        return -ENOMEM;
                k->repdata.keyboard.keysyms = t;

                t = realloc(k->repdata.keyboard.codepoints, sizeof(*t) * n_syms);
                if (!t)
                        return -ENOMEM;
                k->repdata.keyboard.codepoints = t;

                k->n_syms = n_syms;
        }

        dst->type = IDEV_DATA_KEYBOARD;
        dst->resync = resync;
        kev = &dst->keyboard;
        kev->ascii = guess_ascii(k->xkb_state, code, n_syms, keysyms);
        kev->value = value;
        kev->keycode = code;
        kev->mods = 0;
        kev->consumed_mods = 0;
        kev->n_syms = n_syms;
        memcpy(kev->keysyms, keysyms, sizeof(*keysyms) * n_syms);

        for (i = 0; i < n_syms; ++i) {
                kev->codepoints[i] = xkb_keysym_to_utf32(keysyms[i]);
                if (!kev->codepoints[i])
                        kev->codepoints[i] = 0xffffffffUL;
        }

        for (i = 0; i < IDEV_KBDMOD_CNT; ++i) {
                int r;

                if (k->kbdmap->modmap[i] == XKB_MOD_INVALID)
                        continue;

                r = xkb_state_mod_index_is_active(k->xkb_state, k->kbdmap->modmap[i], XKB_STATE_MODS_EFFECTIVE);
                if (r > 0)
                        kev->mods |= 1 << i;

                r = xkb_state_mod_index_is_consumed(k->xkb_state, code + KBDXKB_SHIFT, k->kbdmap->modmap[i]);
                if (r > 0)
                        kev->consumed_mods |= 1 << i;
        }

        return 0;
}

static void keyboard_repeat(idev_keyboard *k) {
        idev_data *evdata = &k->evdata;
        idev_data *repdata = &k->repdata;
        idev_data_keyboard *evkbd = &evdata->keyboard;
        idev_data_keyboard *repkbd = &repdata->keyboard;
        const xkb_keysym_t *keysyms;
        idev_device *d = &k->device;
        bool repeats;
        int r, num;

        if (evdata->resync) {
                /*
                 * We received a re-sync event. During re-sync, any number of
                 * key-events may have been lost and sync-events may be
                 * re-ordered. Always disable key-repeat for those events. Any
                 * following event will trigger it again.
                 */

                k->repeating = false;
                keyboard_arm(k, 0);
                return;
        }

        repeats = xkb_keymap_key_repeats(k->kbdmap->xkb_keymap, evkbd->keycode + KBDXKB_SHIFT);

        if (k->repeating && repkbd->keycode == evkbd->keycode) {
                /*
                 * We received an event for the key we currently repeat. If it
                 * was released, stop key-repeat. Otherwise, ignore the event.
                 */

                if (evkbd->value == KBDKEY_UP) {
                        k->repeating = false;
                        keyboard_arm(k, 0);
                }
        } else if (evkbd->value == KBDKEY_DOWN && repeats) {
                /*
                 * We received a key-down event for a key that repeats. The
                 * previous condition caught keys we already repeat, so we know
                 * this is a different key or no key-repeat is running. Start
                 * new key-repeat.
                 */

                errno = 0;
                num = xkb_state_key_get_syms(k->xkb_state, evkbd->keycode + KBDXKB_SHIFT, &keysyms);
                if (num < 0)
                        r = errno > 0 ? errno : -EFAULT;
                else
                        r = keyboard_fill(k, repdata, false, evkbd->keycode, KBDKEY_REPEAT, num, keysyms);

                if (r < 0) {
                        log_debug("idev-keyboard: %s/%s: cannot set key-repeat: %s",
                                  d->session->name, d->name, strerror(-r));
                        k->repeating = false;
                        keyboard_arm(k, 0);
                } else {
                        k->repeating = true;
                        keyboard_arm(k, k->repeat_delay);
                }
        } else if (k->repeating && !repeats) {
                /*
                 * We received an event for a key that does not repeat, but we
                 * currently repeat a previously received key. The new key is
                 * usually a modifier, but might be any kind of key. In this
                 * case, we continue repeating the old key, but update the
                 * symbols according to the new state.
                 */

                errno = 0;
                num = xkb_state_key_get_syms(k->xkb_state, repkbd->keycode + KBDXKB_SHIFT, &keysyms);
                if (num < 0)
                        r = errno > 0 ? errno : -EFAULT;
                else
                        r = keyboard_fill(k, repdata, false, repkbd->keycode, KBDKEY_REPEAT, num, keysyms);

                if (r < 0) {
                        log_debug("idev-keyboard: %s/%s: cannot update key-repeat: %s",
                                  d->session->name, d->name, strerror(-r));
                        k->repeating = false;
                        keyboard_arm(k, 0);
                }
        }
}

static int keyboard_feed_evdev(idev_keyboard *k, idev_data *data) {
        struct input_event *ev = &data->evdev.event;
        enum xkb_state_component compch;
        const xkb_keysym_t *keysyms;
        idev_device *d = &k->device;
        int num, r;

        if (ev->type != EV_KEY || ev->value > KBDKEY_DOWN)
                return 0;

        /* TODO: We should audit xkb-actions, whether they need @resync as
         * flag. Most actions should just be executed, however, there might
         * be actions that depend on modifier-orders. Those should be
         * suppressed. */

        num = xkb_state_key_get_syms(k->xkb_state, ev->code + KBDXKB_SHIFT, &keysyms);
        compch = xkb_state_update_key(k->xkb_state, ev->code + KBDXKB_SHIFT, ev->value);

        if (compch & XKB_STATE_LEDS) {
                /* TODO: update LEDs */
        }

        if (num < 0) {
                r = num;
                goto error;
        }

        r = keyboard_fill(k, &k->evdata, data->resync, ev->code, ev->value, num, keysyms);
        if (r < 0)
                goto error;

        keyboard_repeat(k);
        return keyboard_raise_data(k, &k->evdata);

error:
        log_debug("idev-keyboard: %s/%s: cannot handle event: %s",
                  d->session->name, d->name, strerror(-r));
        k->repeating = false;
        keyboard_arm(k, 0);
        return 0;
}

static int keyboard_feed(idev_device *d, idev_data *data) {
        idev_keyboard *k = keyboard_from_device(d);

        switch (data->type) {
        case IDEV_DATA_RESYNC:
                /*
                 * If the underlying device is re-synced, key-events might be
                 * sent re-ordered. Thus, we don't know which key was pressed
                 * last. Key-repeat might get confused, hence, disable it
                 * during re-syncs. The first following event will enable it
                 * again.
                 */

                k->repeating = false;
                keyboard_arm(k, 0);
                return 0;
        case IDEV_DATA_EVDEV:
                return keyboard_feed_evdev(k, data);
        default:
                return 0;
        }
}

static int keyboard_update_kbdmap(idev_keyboard *k) {
        idev_device *d = &k->device;
        struct xkb_state *state;
        kbdmap *km;
        int r;

        assert(k);

        km = k->kbdctx->kbdmap;
        if (km == k->kbdmap)
                return 0;

        errno = 0;
        state = xkb_state_new(km->xkb_keymap);
        if (!state) {
                r = errno > 0 ? -errno : -EFAULT;
                goto error;
        }

        kbdmap_unref(k->kbdmap);
        k->kbdmap = kbdmap_ref(km);
        xkb_state_unref(k->xkb_state);
        k->xkb_state = state;

        /* TODO: On state-change, we should trigger a resync so the whole
         * event-state is flushed into the new xkb-state. libevdev currently
         * does not support that, though. */

        return 0;

error:
        log_debug("idev-keyboard: %s/%s: cannot adopt new keymap: %s",
                  d->session->name, d->name, strerror(-r));
        return r;
}

static const idev_device_vtable keyboard_vtable = {
        .free                   = keyboard_free,
        .feed                   = keyboard_feed,
};
