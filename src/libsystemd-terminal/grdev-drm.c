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

#include <fcntl.h>
#include <inttypes.h>
#include <libudev.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

/* Yuck! DRM headers need system headers included first.. but we have to
 * include it before util/missing.h to avoid redefining ioctl bits */
#include <drm.h>
#include <drm_fourcc.h>
#include <drm_mode.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "hashmap.h"
#include "macro.h"
#include "util.h"
#include "bus-util.h"
#include "grdev.h"
#include "grdev-internal.h"

#define GRDRM_MAX_TRIES (16)

typedef struct grdrm_object grdrm_object;
typedef struct grdrm_plane grdrm_plane;
typedef struct grdrm_connector grdrm_connector;
typedef struct grdrm_encoder grdrm_encoder;
typedef struct grdrm_crtc grdrm_crtc;

typedef struct grdrm_fb grdrm_fb;
typedef struct grdrm_pipe grdrm_pipe;
typedef struct grdrm_card grdrm_card;
typedef struct unmanaged_card unmanaged_card;
typedef struct managed_card managed_card;

/*
 * Objects
 */

enum {
        GRDRM_TYPE_CRTC,
        GRDRM_TYPE_ENCODER,
        GRDRM_TYPE_CONNECTOR,
        GRDRM_TYPE_PLANE,
        GRDRM_TYPE_CNT
};

struct grdrm_object {
        grdrm_card *card;
        uint32_t id;
        uint32_t index;
        unsigned int type;
        void (*free_fn) (grdrm_object *object);

        bool present : 1;
        bool assigned : 1;
};

struct grdrm_plane {
        grdrm_object object;

        struct {
                uint32_t used_crtc;
                uint32_t used_fb;
                uint32_t gamma_size;

                uint32_t n_crtcs;
                uint32_t max_crtcs;
                uint32_t *crtcs;
                uint32_t n_formats;
                uint32_t max_formats;
                uint32_t *formats;
        } kern;
};

struct grdrm_connector {
        grdrm_object object;

        struct {
                uint32_t type;
                uint32_t type_id;
                uint32_t used_encoder;
                uint32_t connection;
                uint32_t mm_width;
                uint32_t mm_height;
                uint32_t subpixel;

                uint32_t n_encoders;
                uint32_t max_encoders;
                uint32_t *encoders;
                uint32_t n_modes;
                uint32_t max_modes;
                struct drm_mode_modeinfo *modes;
                uint32_t n_props;
                uint32_t max_props;
                uint32_t *prop_ids;
                uint64_t *prop_values;
        } kern;
};

struct grdrm_encoder {
        grdrm_object object;

        struct {
                uint32_t type;
                uint32_t used_crtc;

                uint32_t n_crtcs;
                uint32_t max_crtcs;
                uint32_t *crtcs;
                uint32_t n_clones;
                uint32_t max_clones;
                uint32_t *clones;
        } kern;
};

struct grdrm_crtc {
        grdrm_object object;

        struct {
                uint32_t used_fb;
                uint32_t fb_offset_x;
                uint32_t fb_offset_y;
                uint32_t gamma_size;

                uint32_t n_used_connectors;
                uint32_t max_used_connectors;
                uint32_t *used_connectors;

                bool mode_set;
                struct drm_mode_modeinfo mode;
        } kern;

        struct {
                bool set;
                uint32_t fb;
                uint32_t fb_x;
                uint32_t fb_y;
                uint32_t gamma;

                uint32_t n_connectors;
                uint32_t *connectors;

                bool mode_set;
                struct drm_mode_modeinfo mode;
        } old;

        struct {
                struct drm_mode_modeinfo mode;
                uint32_t n_connectors;
                uint32_t max_connectors;
                uint32_t *connectors;
        } set;

        grdrm_pipe *pipe;

        bool applied : 1;
};

#define GRDRM_OBJECT_INIT(_card, _id, _index, _type, _free_fn) ((grdrm_object){ \
                .card = (_card), \
                .id = (_id), \
                .index = (_index), \
                .type = (_type), \
                .free_fn = (_free_fn), \
        })

grdrm_object *grdrm_find_object(grdrm_card *card, uint32_t id);
int grdrm_object_add(grdrm_object *object);
grdrm_object *grdrm_object_free(grdrm_object *object);

DEFINE_TRIVIAL_CLEANUP_FUNC(grdrm_object*, grdrm_object_free);

int grdrm_plane_new(grdrm_plane **out, grdrm_card *card, uint32_t id, uint32_t index);
int grdrm_connector_new(grdrm_connector **out, grdrm_card *card, uint32_t id, uint32_t index);
int grdrm_encoder_new(grdrm_encoder **out, grdrm_card *card, uint32_t id, uint32_t index);
int grdrm_crtc_new(grdrm_crtc **out, grdrm_card *card, uint32_t id, uint32_t index);

#define plane_from_object(_obj) container_of((_obj), grdrm_plane, object)
#define connector_from_object(_obj) container_of((_obj), grdrm_connector, object)
#define encoder_from_object(_obj) container_of((_obj), grdrm_encoder, object)
#define crtc_from_object(_obj) container_of((_obj), grdrm_crtc, object)

/*
 * Framebuffers
 */

struct grdrm_fb {
        grdev_fb base;
        grdrm_card *card;
        uint32_t id;
        uint32_t handles[4];
        uint32_t offsets[4];
        uint32_t sizes[4];
        uint32_t flipid;
};

static int grdrm_fb_new(grdrm_fb **out, grdrm_card *card, const struct drm_mode_modeinfo *mode);
grdrm_fb *grdrm_fb_free(grdrm_fb *fb);

DEFINE_TRIVIAL_CLEANUP_FUNC(grdrm_fb*, grdrm_fb_free);

#define fb_from_base(_fb) container_of((_fb), grdrm_fb, base)

/*
 * Pipes
 */

struct grdrm_pipe {
        grdev_pipe base;
        grdrm_crtc *crtc;
        uint32_t counter;
};

#define grdrm_pipe_from_base(_e) container_of((_e), grdrm_pipe, base)

#define GRDRM_PIPE_NAME_MAX (GRDRM_CARD_NAME_MAX + 1 + DECIMAL_STR_MAX(uint32_t))

static const grdev_pipe_vtable grdrm_pipe_vtable;

static int grdrm_pipe_new(grdrm_pipe **out, grdrm_crtc *crtc, struct drm_mode_modeinfo *mode, size_t n_fbs);

/*
 * Cards
 */

struct grdrm_card {
        grdev_card base;

        int fd;
        sd_event_source *fd_src;

        uint32_t n_crtcs;
        uint32_t n_encoders;
        uint32_t n_connectors;
        uint32_t n_planes;
        uint32_t max_ids;
        Hashmap *object_map;

        bool async_hotplug : 1;
        bool hotplug : 1;
        bool running : 1;
        bool ready : 1;
        bool cap_dumb : 1;
        bool cap_monotonic : 1;
};

struct unmanaged_card {
        grdrm_card card;
        char *devnode;
};

struct managed_card {
        grdrm_card card;
        dev_t devnum;

        sd_bus_slot *slot_pause_device;
        sd_bus_slot *slot_resume_device;
        sd_bus_slot *slot_take_device;

        bool requested : 1;             /* TakeDevice() was sent */
        bool acquired : 1;              /* TakeDevice() was successful */
        bool master : 1;                /* we are DRM-Master */
};

#define grdrm_card_from_base(_e) container_of((_e), grdrm_card, base)
#define unmanaged_card_from_base(_e) \
        container_of(grdrm_card_from_base(_e), unmanaged_card, card)
#define managed_card_from_base(_e) \
        container_of(grdrm_card_from_base(_e), managed_card, card)

#define GRDRM_CARD_INIT(_vtable, _session) ((grdrm_card){ \
                .base = GRDEV_CARD_INIT((_vtable), (_session)), \
                .fd = -1, \
                .max_ids = 32, \
        })

#define GRDRM_CARD_NAME_MAX (6 + DECIMAL_STR_MAX(unsigned) * 2)

static const grdev_card_vtable unmanaged_card_vtable;
static const grdev_card_vtable managed_card_vtable;

static int grdrm_card_open(grdrm_card *card, int dev_fd);
static void grdrm_card_close(grdrm_card *card);
static bool grdrm_card_async(grdrm_card *card, int r);

/*
 * The page-flip event of the kernel provides 64bit of arbitrary user-data. As
 * drivers tend to drop events on intermediate deep mode-sets or because we
 * might receive events during session activation, we try to avoid allocaing
 * dynamic data on those events. Instead, we safe the CRTC id plus a 32bit
 * counter in there. This way, we only get 32bit counters, not 64bit, but that
 * should be more than enough. On the bright side, we no longer care whether we
 * lose events. No memory leaks will occur.
 * Modern DRM drivers might be fixed to no longer leak events, but we want to
 * be safe. And associating dynamically allocated data with those events is
 * kinda ugly, anyway.
 */

static uint64_t grdrm_encode_vblank_data(uint32_t id, uint32_t counter) {
        return id | ((uint64_t)counter << 32);
}

static void grdrm_decode_vblank_data(uint64_t data, uint32_t *out_id, uint32_t *out_counter) {
        if (out_id)
                *out_id = data & 0xffffffffU;
        if (out_counter)
                *out_counter = (data >> 32) & 0xffffffffU;
}

static bool grdrm_modes_compatible(const struct drm_mode_modeinfo *a, const struct drm_mode_modeinfo *b) {
        assert(a);
        assert(b);

        /* Test whether both modes are compatible according to our internal
         * assumptions on modes. This comparison is highly dependent on how
         * we treat modes in grdrm. If we export mode details, we need to
         * make this comparison much stricter. */

        if (a->hdisplay != b->hdisplay)
                return false;
        if (a->vdisplay != b->vdisplay)
                return false;
        if (a->vrefresh != b->vrefresh)
                return false;

        return true;
}

/*
 * Objects
 */

grdrm_object *grdrm_find_object(grdrm_card *card, uint32_t id) {
        assert_return(card, NULL);

        return id > 0 ? hashmap_get(card->object_map, UINT32_TO_PTR(id)) : NULL;
}

int grdrm_object_add(grdrm_object *object) {
        int r;

        assert(object);
        assert(object->card);
        assert(object->id > 0);
        assert(IN_SET(object->type, GRDRM_TYPE_CRTC, GRDRM_TYPE_ENCODER, GRDRM_TYPE_CONNECTOR, GRDRM_TYPE_PLANE));
        assert(object->free_fn);

        if (object->index >= 32)
                log_debug("grdrm: %s: object index exceeds 32bit masks: type=%u, index=%" PRIu32,
                          object->card->base.name, object->type, object->index);

        r = hashmap_put(object->card->object_map, UINT32_TO_PTR(object->id), object);
        if (r < 0)
                return r;

        return 0;
}

grdrm_object *grdrm_object_free(grdrm_object *object) {
        if (!object)
                return NULL;

        assert(object->card);
        assert(object->id > 0);
        assert(IN_SET(object->type, GRDRM_TYPE_CRTC, GRDRM_TYPE_ENCODER, GRDRM_TYPE_CONNECTOR, GRDRM_TYPE_PLANE));
        assert(object->free_fn);

        hashmap_remove_value(object->card->object_map, UINT32_TO_PTR(object->id), object);

        object->free_fn(object);
        return NULL;
}

/*
 * Planes
 */

static void plane_free(grdrm_object *object) {
        grdrm_plane *plane = plane_from_object(object);

        free(plane->kern.formats);
        free(plane->kern.crtcs);
        free(plane);
}

int grdrm_plane_new(grdrm_plane **out, grdrm_card *card, uint32_t id, uint32_t index) {
        _cleanup_(grdrm_object_freep) grdrm_object *object = NULL;
        grdrm_plane *plane;
        int r;

        assert(card);

        plane = new0(grdrm_plane, 1);
        if (!plane)
                return -ENOMEM;

        object = &plane->object;
        *object = GRDRM_OBJECT_INIT(card, id, index, GRDRM_TYPE_PLANE, plane_free);

        plane->kern.max_crtcs = 32;
        plane->kern.crtcs = new0(uint32_t, plane->kern.max_crtcs);
        if (!plane->kern.crtcs)
                return -ENOMEM;

        plane->kern.max_formats = 32;
        plane->kern.formats = new0(uint32_t, plane->kern.max_formats);
        if (!plane->kern.formats)
                return -ENOMEM;

        r = grdrm_object_add(object);
        if (r < 0)
                return r;

        if (out)
                *out = plane;
        object = NULL;
        return 0;
}

static int grdrm_plane_resync(grdrm_plane *plane) {
        grdrm_card *card = plane->object.card;
        size_t tries;
        int r;

        assert(plane);

        for (tries = 0; tries < GRDRM_MAX_TRIES; ++tries) {
                struct drm_mode_get_plane res;
                grdrm_object *object;
                bool resized = false;
                Iterator iter;

                zero(res);
                res.plane_id = plane->object.id;
                res.format_type_ptr = PTR_TO_UINT64(plane->kern.formats);
                res.count_format_types = plane->kern.max_formats;

                r = ioctl(card->fd, DRM_IOCTL_MODE_GETPLANE, &res);
                if (r < 0) {
                        r = -errno;
                        if (r == -ENOENT) {
                                card->async_hotplug = true;
                                r = 0;
                                log_debug("grdrm: %s: plane %u removed during resync",
                                          card->base.name, plane->object.id);
                        } else {
                                log_debug_errno(errno, "grdrm: %s: cannot retrieve plane %u: %m",
                                                card->base.name, plane->object.id);
                        }

                        return r;
                }

                plane->kern.n_crtcs = 0;
                memzero(plane->kern.crtcs, sizeof(uint32_t) * plane->kern.max_crtcs);

                HASHMAP_FOREACH(object, card->object_map, iter) {
                        if (object->type != GRDRM_TYPE_CRTC || object->index >= 32)
                                continue;
                        if (!(res.possible_crtcs & (1 << object->index)))
                                continue;
                        if (plane->kern.n_crtcs >= 32) {
                                log_debug("grdrm: %s: possible_crtcs of plane %" PRIu32 " exceeds 32bit mask",
                                          card->base.name, plane->object.id);
                                continue;
                        }

                        plane->kern.crtcs[plane->kern.n_crtcs++] = object->id;
                }

                if (res.count_format_types > plane->kern.max_formats) {
                        uint32_t max, *t;

                        max = ALIGN_POWER2(res.count_format_types);
                        if (!max || max > UINT16_MAX) {
                                log_debug("grdrm: %s: excessive plane resource limit: %" PRIu32, card->base.name, max);
                                return -ERANGE;
                        }

                        t = realloc(plane->kern.formats, sizeof(*t) * max);
                        if (!t)
                                return -ENOMEM;

                        plane->kern.formats = t;
                        plane->kern.max_formats = max;
                        resized = true;
                }

                if (resized)
                        continue;

                plane->kern.n_formats = res.count_format_types;
                plane->kern.used_crtc = res.crtc_id;
                plane->kern.used_fb = res.fb_id;
                plane->kern.gamma_size = res.gamma_size;

                break;
        }

        if (tries >= GRDRM_MAX_TRIES) {
                log_debug("grdrm: %s: plane %u not settled for retrieval", card->base.name, plane->object.id);
                return -EFAULT;
        }

        return 0;
}

/*
 * Connectors
 */

static void connector_free(grdrm_object *object) {
        grdrm_connector *connector = connector_from_object(object);

        free(connector->kern.prop_values);
        free(connector->kern.prop_ids);
        free(connector->kern.modes);
        free(connector->kern.encoders);
        free(connector);
}

int grdrm_connector_new(grdrm_connector **out, grdrm_card *card, uint32_t id, uint32_t index) {
        _cleanup_(grdrm_object_freep) grdrm_object *object = NULL;
        grdrm_connector *connector;
        int r;

        assert(card);

        connector = new0(grdrm_connector, 1);
        if (!connector)
                return -ENOMEM;

        object = &connector->object;
        *object = GRDRM_OBJECT_INIT(card, id, index, GRDRM_TYPE_CONNECTOR, connector_free);

        connector->kern.max_encoders = 32;
        connector->kern.encoders = new0(uint32_t, connector->kern.max_encoders);
        if (!connector->kern.encoders)
                return -ENOMEM;

        connector->kern.max_modes = 32;
        connector->kern.modes = new0(struct drm_mode_modeinfo, connector->kern.max_modes);
        if (!connector->kern.modes)
                return -ENOMEM;

        connector->kern.max_props = 32;
        connector->kern.prop_ids = new0(uint32_t, connector->kern.max_props);
        connector->kern.prop_values = new0(uint64_t, connector->kern.max_props);
        if (!connector->kern.prop_ids || !connector->kern.prop_values)
                return -ENOMEM;

        r = grdrm_object_add(object);
        if (r < 0)
                return r;

        if (out)
                *out = connector;
        object = NULL;
        return 0;
}

static int grdrm_connector_resync(grdrm_connector *connector) {
        grdrm_card *card = connector->object.card;
        size_t tries;
        int r;

        assert(connector);

        for (tries = 0; tries < GRDRM_MAX_TRIES; ++tries) {
                struct drm_mode_get_connector res;
                bool resized = false;
                uint32_t max;

                zero(res);
                res.connector_id = connector->object.id;
                res.encoders_ptr = PTR_TO_UINT64(connector->kern.encoders);
                res.props_ptr = PTR_TO_UINT64(connector->kern.prop_ids);
                res.prop_values_ptr = PTR_TO_UINT64(connector->kern.prop_values);
                res.count_encoders = connector->kern.max_encoders;
                res.count_props = connector->kern.max_props;

                /* The kernel reads modes from the EDID information only if we
                 * pass count_modes==0. This is a legacy hack for libdrm (which
                 * called every ioctl twice). Now we have to adopt.. *sigh*.
                 * If we never received an hotplug event, there's no reason to
                 * sync modes. EDID reads are heavy, so skip that if not
                 * required. */
                if (card->hotplug) {
                        if (tries > 0) {
                                res.modes_ptr = PTR_TO_UINT64(connector->kern.modes);
                                res.count_modes = connector->kern.max_modes;
                        } else {
                                resized = true;
                        }
                }

                r = ioctl(card->fd, DRM_IOCTL_MODE_GETCONNECTOR, &res);
                if (r < 0) {
                        r = -errno;
                        if (r == -ENOENT) {
                                card->async_hotplug = true;
                                r = 0;
                                log_debug("grdrm: %s: connector %u removed during resync",
                                          card->base.name, connector->object.id);
                        } else {
                                log_debug_errno(errno, "grdrm: %s: cannot retrieve connector %u: %m",
                                                card->base.name, connector->object.id);
                        }

                        return r;
                }

                if (res.count_encoders > connector->kern.max_encoders) {
                        uint32_t *t;

                        max = ALIGN_POWER2(res.count_encoders);
                        if (!max || max > UINT16_MAX) {
                                log_debug("grdrm: %s: excessive connector resource limit: %" PRIu32, card->base.name, max);
                                return -ERANGE;
                        }

                        t = realloc(connector->kern.encoders, sizeof(*t) * max);
                        if (!t)
                                return -ENOMEM;

                        connector->kern.encoders = t;
                        connector->kern.max_encoders = max;
                        resized = true;
                }

                if (res.count_modes > connector->kern.max_modes) {
                        struct drm_mode_modeinfo *t;

                        max = ALIGN_POWER2(res.count_modes);
                        if (!max || max > UINT16_MAX) {
                                log_debug("grdrm: %s: excessive connector resource limit: %" PRIu32, card->base.name, max);
                                return -ERANGE;
                        }

                        t = realloc(connector->kern.modes, sizeof(*t) * max);
                        if (!t)
                                return -ENOMEM;

                        connector->kern.modes = t;
                        connector->kern.max_modes = max;
                        resized = true;
                }

                if (res.count_props > connector->kern.max_props) {
                        uint32_t *tids;
                        uint64_t *tvals;

                        max = ALIGN_POWER2(res.count_props);
                        if (!max || max > UINT16_MAX) {
                                log_debug("grdrm: %s: excessive connector resource limit: %" PRIu32, card->base.name, max);
                                return -ERANGE;
                        }

                        tids = realloc(connector->kern.prop_ids, sizeof(*tids) * max);
                        if (!tids)
                                return -ENOMEM;
                        connector->kern.prop_ids = tids;

                        tvals = realloc(connector->kern.prop_values, sizeof(*tvals) * max);
                        if (!tvals)
                                return -ENOMEM;
                        connector->kern.prop_values = tvals;

                        connector->kern.max_props = max;
                        resized = true;
                }

                if (resized)
                        continue;

                connector->kern.n_encoders = res.count_encoders;
                connector->kern.n_props = res.count_props;
                connector->kern.type = res.connector_type;
                connector->kern.type_id = res.connector_type_id;
                connector->kern.used_encoder = res.encoder_id;
                connector->kern.connection = res.connection;
                connector->kern.mm_width = res.mm_width;
                connector->kern.mm_height = res.mm_height;
                connector->kern.subpixel = res.subpixel;
                if (res.modes_ptr == PTR_TO_UINT64(connector->kern.modes))
                        connector->kern.n_modes = res.count_modes;

                break;
        }

        if (tries >= GRDRM_MAX_TRIES) {
                log_debug("grdrm: %s: connector %u not settled for retrieval", card->base.name, connector->object.id);
                return -EFAULT;
        }

        return 0;
}

/*
 * Encoders
 */

static void encoder_free(grdrm_object *object) {
        grdrm_encoder *encoder = encoder_from_object(object);

        free(encoder->kern.clones);
        free(encoder->kern.crtcs);
        free(encoder);
}

int grdrm_encoder_new(grdrm_encoder **out, grdrm_card *card, uint32_t id, uint32_t index) {
        _cleanup_(grdrm_object_freep) grdrm_object *object = NULL;
        grdrm_encoder *encoder;
        int r;

        assert(card);

        encoder = new0(grdrm_encoder, 1);
        if (!encoder)
                return -ENOMEM;

        object = &encoder->object;
        *object = GRDRM_OBJECT_INIT(card, id, index, GRDRM_TYPE_ENCODER, encoder_free);

        encoder->kern.max_crtcs = 32;
        encoder->kern.crtcs = new0(uint32_t, encoder->kern.max_crtcs);
        if (!encoder->kern.crtcs)
                return -ENOMEM;

        encoder->kern.max_clones = 32;
        encoder->kern.clones = new0(uint32_t, encoder->kern.max_clones);
        if (!encoder->kern.clones)
                return -ENOMEM;

        r = grdrm_object_add(object);
        if (r < 0)
                return r;

        if (out)
                *out = encoder;
        object = NULL;
        return 0;
}

static int grdrm_encoder_resync(grdrm_encoder *encoder) {
        grdrm_card *card = encoder->object.card;
        struct drm_mode_get_encoder res;
        grdrm_object *object;
        Iterator iter;
        int r;

        assert(encoder);

        zero(res);
        res.encoder_id = encoder->object.id;

        r = ioctl(card->fd, DRM_IOCTL_MODE_GETENCODER, &res);
        if (r < 0) {
                r = -errno;
                if (r == -ENOENT) {
                        card->async_hotplug = true;
                        r = 0;
                        log_debug("grdrm: %s: encoder %u removed during resync",
                                  card->base.name, encoder->object.id);
                } else {
                        log_debug_errno(errno, "grdrm: %s: cannot retrieve encoder %u: %m",
                                        card->base.name, encoder->object.id);
                }

                return r;
        }

        encoder->kern.type = res.encoder_type;
        encoder->kern.used_crtc = res.crtc_id;

        encoder->kern.n_crtcs = 0;
        memzero(encoder->kern.crtcs, sizeof(uint32_t) * encoder->kern.max_crtcs);

        HASHMAP_FOREACH(object, card->object_map, iter) {
                if (object->type != GRDRM_TYPE_CRTC || object->index >= 32)
                        continue;
                if (!(res.possible_crtcs & (1 << object->index)))
                        continue;
                if (encoder->kern.n_crtcs >= 32) {
                        log_debug("grdrm: %s: possible_crtcs exceeds 32bit mask", card->base.name);
                        continue;
                }

                encoder->kern.crtcs[encoder->kern.n_crtcs++] = object->id;
        }

        encoder->kern.n_clones = 0;
        memzero(encoder->kern.clones, sizeof(uint32_t) * encoder->kern.max_clones);

        HASHMAP_FOREACH(object, card->object_map, iter) {
                if (object->type != GRDRM_TYPE_ENCODER || object->index >= 32)
                        continue;
                if (!(res.possible_clones & (1 << object->index)))
                        continue;
                if (encoder->kern.n_clones >= 32) {
                        log_debug("grdrm: %s: possible_encoders exceeds 32bit mask", card->base.name);
                        continue;
                }

                encoder->kern.clones[encoder->kern.n_clones++] = object->id;
        }

        return 0;
}

/*
 * Crtcs
 */

static void crtc_free(grdrm_object *object) {
        grdrm_crtc *crtc = crtc_from_object(object);

        if (crtc->pipe)
                grdev_pipe_free(&crtc->pipe->base);
        free(crtc->set.connectors);
        free(crtc->old.connectors);
        free(crtc->kern.used_connectors);
        free(crtc);
}

int grdrm_crtc_new(grdrm_crtc **out, grdrm_card *card, uint32_t id, uint32_t index) {
        _cleanup_(grdrm_object_freep) grdrm_object *object = NULL;
        grdrm_crtc *crtc;
        int r;

        assert(card);

        crtc = new0(grdrm_crtc, 1);
        if (!crtc)
                return -ENOMEM;

        object = &crtc->object;
        *object = GRDRM_OBJECT_INIT(card, id, index, GRDRM_TYPE_CRTC, crtc_free);

        crtc->kern.max_used_connectors = 32;
        crtc->kern.used_connectors = new0(uint32_t, crtc->kern.max_used_connectors);
        if (!crtc->kern.used_connectors)
                return -ENOMEM;

        crtc->old.connectors = new0(uint32_t, crtc->kern.max_used_connectors);
        if (!crtc->old.connectors)
                return -ENOMEM;

        r = grdrm_object_add(object);
        if (r < 0)
                return r;

        if (out)
                *out = crtc;
        object = NULL;
        return 0;
}

static int grdrm_crtc_resync(grdrm_crtc *crtc) {
        grdrm_card *card = crtc->object.card;
        struct drm_mode_crtc res = { .crtc_id = crtc->object.id };
        int r;

        assert(crtc);

        /* make sure we can cache any combination later */
        if (card->n_connectors > crtc->kern.max_used_connectors) {
                uint32_t max, *t;

                max = ALIGN_POWER2(card->n_connectors);
                if (!max)
                        return -ENOMEM;

                t = realloc_multiply(crtc->kern.used_connectors, sizeof(*t), max);
                if (!t)
                        return -ENOMEM;

                crtc->kern.used_connectors = t;
                crtc->kern.max_used_connectors = max;

                if (!crtc->old.set) {
                        crtc->old.connectors = calloc(sizeof(*t), max);
                        if (!crtc->old.connectors)
                                return -ENOMEM;
                }
        }

        /* GETCRTC doesn't return connectors. We have to read all
         * encoder-state and deduce the setup ourselves.. */
        crtc->kern.n_used_connectors = 0;

        r = ioctl(card->fd, DRM_IOCTL_MODE_GETCRTC, &res);
        if (r < 0) {
                r = -errno;
                if (r == -ENOENT) {
                        card->async_hotplug = true;
                        r = 0;
                        log_debug("grdrm: %s: crtc %u removed during resync",
                                  card->base.name, crtc->object.id);
                } else {
                        log_debug_errno(errno, "grdrm: %s: cannot retrieve crtc %u: %m",
                                        card->base.name, crtc->object.id);
                }

                return r;
        }

        crtc->kern.used_fb = res.fb_id;
        crtc->kern.fb_offset_x = res.x;
        crtc->kern.fb_offset_y = res.y;
        crtc->kern.gamma_size = res.gamma_size;
        crtc->kern.mode_set = res.mode_valid;
        crtc->kern.mode = res.mode;

        return 0;
}

static void grdrm_crtc_assign(grdrm_crtc *crtc, grdrm_connector *connector) {
        uint32_t n_connectors;
        int r;

        assert(crtc);
        assert(!crtc->object.assigned);
        assert(!connector || !connector->object.assigned);

        /* always mark both as assigned; even if assignments cannot be set */
        crtc->object.assigned = true;
        if (connector)
                connector->object.assigned = true;

        /* we will support hw clone mode in the future */
        n_connectors = connector ? 1 : 0;

        /* bail out if configuration is preserved */
        if (crtc->set.n_connectors == n_connectors &&
            (n_connectors == 0 || crtc->set.connectors[0] == connector->object.id))
                return;

        crtc->applied = false;
        crtc->set.n_connectors = 0;

        if (n_connectors > crtc->set.max_connectors) {
                uint32_t max, *t;

                max = ALIGN_POWER2(n_connectors);
                if (!max) {
                        r = -ENOMEM;
                        goto error;
                }

                t = realloc(crtc->set.connectors, sizeof(*t) * max);
                if (!t) {
                        r = -ENOMEM;
                        goto error;
                }

                crtc->set.connectors = t;
                crtc->set.max_connectors = max;
        }

        if (connector) {
                struct drm_mode_modeinfo *m, *pref = NULL;
                uint32_t i;

                for (i = 0; i < connector->kern.n_modes; ++i) {
                        m = &connector->kern.modes[i];

                        /* ignore 3D modes by default */
                        if (m->flags & DRM_MODE_FLAG_3D_MASK)
                                continue;

                        if (!pref) {
                                pref = m;
                                continue;
                        }

                        /* use PREFERRED over non-PREFERRED */
                        if ((pref->type & DRM_MODE_TYPE_PREFERRED) &&
                            !(m->type & DRM_MODE_TYPE_PREFERRED))
                                continue;

                        /* use DRIVER over non-PREFERRED|DRIVER */
                        if ((pref->type & DRM_MODE_TYPE_DRIVER) &&
                            !(m->type & (DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED)))
                                continue;

                        /* always prefer higher resolution */
                        if (pref->hdisplay > m->hdisplay ||
                            (pref->hdisplay == m->hdisplay && pref->vdisplay > m->vdisplay))
                                continue;

                        pref = m;
                }

                if (pref) {
                        crtc->set.mode = *pref;
                        crtc->set.n_connectors = 1;
                        crtc->set.connectors[0] = connector->object.id;
                        log_debug("grdrm: %s: assigned connector %" PRIu32 " to crtc %" PRIu32 " with mode %s",
                                  crtc->object.card->base.name, connector->object.id, crtc->object.id, pref->name);
                } else {
                        log_debug("grdrm: %s: connector %" PRIu32 " to be assigned but has no valid mode",
                                  crtc->object.card->base.name, connector->object.id);
                }
        }

        return;

error:
        log_debug("grdrm: %s: cannot assign crtc %" PRIu32 ": %s",
                  crtc->object.card->base.name, crtc->object.id, strerror(-r));
}

static void grdrm_crtc_expose(grdrm_crtc *crtc) {
        grdrm_pipe *pipe;
        grdrm_fb *fb;
        size_t i;
        int r;

        assert(crtc);
        assert(crtc->object.assigned);

        if (crtc->set.n_connectors < 1) {
                if (crtc->pipe)
                        grdev_pipe_free(&crtc->pipe->base);
                crtc->pipe = NULL;
                return;
        }

        pipe = crtc->pipe;
        if (pipe) {
                if (pipe->base.width != crtc->set.mode.hdisplay ||
                    pipe->base.height != crtc->set.mode.vdisplay ||
                    pipe->base.vrefresh != crtc->set.mode.vrefresh) {
                        grdev_pipe_free(&pipe->base);
                        crtc->pipe = NULL;
                        pipe = NULL;
                }
        }

        if (crtc->pipe) {
                pipe->base.front = NULL;
                pipe->base.back = NULL;
                for (i = 0; i < pipe->base.max_fbs; ++i) {
                        fb = fb_from_base(pipe->base.fbs[i]);
                        if (fb->id == crtc->kern.used_fb)
                                pipe->base.front = &fb->base;
                        else if (!fb->flipid)
                                pipe->base.back = &fb->base;
                }
        } else {
                r = grdrm_pipe_new(&pipe, crtc, &crtc->set.mode, 2);
                if (r < 0) {
                        log_debug("grdrm: %s: cannot create pipe for crtc %" PRIu32 ": %s",
                                  crtc->object.card->base.name, crtc->object.id, strerror(-r));
                        return;
                }

                for (i = 0; i < pipe->base.max_fbs; ++i) {
                        r = grdrm_fb_new(&fb, crtc->object.card, &crtc->set.mode);
                        if (r < 0) {
                                log_debug("grdrm: %s: cannot allocate framebuffer for crtc %" PRIu32 ": %s",
                                          crtc->object.card->base.name, crtc->object.id, strerror(-r));
                                grdev_pipe_free(&pipe->base);
                                return;
                        }

                        pipe->base.fbs[i] = &fb->base;
                }

                pipe->base.front = NULL;
                pipe->base.back = pipe->base.fbs[0];
                crtc->pipe = pipe;
        }

        grdev_pipe_ready(&crtc->pipe->base, true);
}

static void grdrm_crtc_commit_deep(grdrm_crtc *crtc, grdev_fb *basefb) {
        struct drm_mode_crtc set_crtc = { .crtc_id = crtc->object.id };
        grdrm_card *card = crtc->object.card;
        grdrm_pipe *pipe = crtc->pipe;
        grdrm_fb *fb;
        int r;

        assert(crtc);
        assert(basefb);
        assert(pipe);

        fb = fb_from_base(basefb);

        set_crtc.set_connectors_ptr = PTR_TO_UINT64(crtc->set.connectors);
        set_crtc.count_connectors = crtc->set.n_connectors;
        set_crtc.fb_id = fb->id;
        set_crtc.x = 0;
        set_crtc.y = 0;
        set_crtc.mode_valid = 1;
        set_crtc.mode = crtc->set.mode;

        r = ioctl(card->fd, DRM_IOCTL_MODE_SETCRTC, &set_crtc);
        if (r < 0) {
                r = -errno;
                log_debug_errno(errno, "grdrm: %s: cannot set crtc %" PRIu32 ": %m",
                                card->base.name, crtc->object.id);

                grdrm_card_async(card, r);
                return;
        }

        if (!crtc->applied) {
                log_debug("grdrm: %s: crtc %" PRIu32 " applied via deep modeset",
                          card->base.name, crtc->object.id);
                crtc->applied = true;
        }

        pipe->base.back = NULL;
        pipe->base.front = &fb->base;
        fb->flipid = 0;
        ++pipe->counter;
        pipe->base.flipping = false;
        pipe->base.flip = false;

        /* We cannot schedule dummy page-flips on pipes, hence, the
         * application would have to schedule their own frame-timers.
         * To avoid duplicating that everywhere, we schedule our own
         * timer and raise a fake FRAME event when it fires. */
        grdev_pipe_schedule(&pipe->base, 1);
}

static int grdrm_crtc_commit_flip(grdrm_crtc *crtc, grdev_fb *basefb) {
        struct drm_mode_crtc_page_flip page_flip = { .crtc_id = crtc->object.id };
        grdrm_card *card = crtc->object.card;
        grdrm_pipe *pipe = crtc->pipe;
        grdrm_fb *fb;
        uint32_t cnt;
        int r;

        assert(crtc);
        assert(basefb);
        assert(pipe);

        if (!crtc->applied) {
                if (!grdrm_modes_compatible(&crtc->kern.mode, &crtc->set.mode))
                        return 0;

                /* TODO: Theoretically, we should be able to page-flip to our
                 * framebuffer here. We didn't perform any deep modeset, but the
                 * DRM driver is really supposed to reject our page-flip in case
                 * the FB is not compatible. We then properly fall back to a
                 * deep modeset.
                 * As it turns out, drivers don't to this. Therefore, we need to
                 * perform a full modeset on enter now. We might avoid this in
                 * the future with fixed drivers.. */

                return 0;
        }

        fb = fb_from_base(basefb);

        cnt = ++pipe->counter ? : ++pipe->counter;
        page_flip.fb_id = fb->id;
        page_flip.flags = DRM_MODE_PAGE_FLIP_EVENT;
        page_flip.user_data = grdrm_encode_vblank_data(crtc->object.id, cnt);

        r = ioctl(card->fd, DRM_IOCTL_MODE_PAGE_FLIP, &page_flip);
        if (r < 0) {
                r = -errno;
                /* Avoid excessive logging on EINVAL; it is currently not
                 * possible to see whether cards support page-flipping, so
                 * avoid logging on each frame. */
                if (r != -EINVAL)
                        log_debug_errno(errno, "grdrm: %s: cannot schedule page-flip on crtc %" PRIu32 ": %m",
                                        card->base.name, crtc->object.id);

                if (grdrm_card_async(card, r))
                        return r;

                return 0;
        }

        if (!crtc->applied) {
                log_debug("grdrm: %s: crtc %" PRIu32 " applied via page flip",
                          card->base.name, crtc->object.id);
                crtc->applied = true;
        }

        pipe->base.flipping = true;
        pipe->base.flip = false;
        pipe->counter = cnt;
        fb->flipid = cnt;
        pipe->base.back = NULL;

        /* Raise fake FRAME event if it takes longer than 2
         * frames to receive the pageflip event. We assume the
         * queue ran over or some other error happened. */
        grdev_pipe_schedule(&pipe->base, 2);

        return 1;
}

static void grdrm_crtc_commit(grdrm_crtc *crtc) {
        struct drm_mode_crtc set_crtc = { .crtc_id = crtc->object.id };
        grdrm_card *card = crtc->object.card;
        grdrm_pipe *pipe;
        grdev_fb *fb;
        int r;

        assert(crtc);
        assert(crtc->object.assigned);

        pipe = crtc->pipe;
        if (!pipe) {
                /* If a crtc is not assigned any connector, we want any
                 * previous setup to be cleared, so make sure the CRTC is
                 * disabled. Otherwise, there might be content on the CRTC
                 * while we run, which is not what we want.
                 * If you want to avoid modesets on specific CRTCs, you should
                 * still keep their assignment, but never enable the resulting
                 * pipe. This way, we wouldn't touch it at all. */
                if (!crtc->applied) {
                        crtc->applied = true;
                        r = ioctl(card->fd, DRM_IOCTL_MODE_SETCRTC, &set_crtc);
                        if (r < 0) {
                                r = -errno;
                                log_debug_errno(errno, "grdrm: %s: cannot shutdown crtc %" PRIu32 ": %m",
                                                card->base.name, crtc->object.id);

                                grdrm_card_async(card, r);
                                return;
                        }

                        log_debug("grdrm: %s: crtc %" PRIu32 " applied via shutdown",
                                  card->base.name, crtc->object.id);
                }

                return;
        }

        /* we always fully ignore disabled pipes */
        if (!pipe->base.enabled)
                return;

        assert(crtc->set.n_connectors > 0);

        if (pipe->base.flip)
                fb = pipe->base.back;
        else if (!crtc->applied)
                fb = pipe->base.front;
        else
                return;

        if (!fb)
                return;

        r = grdrm_crtc_commit_flip(crtc, fb);
        if (r == 0) {
                /* in case we couldn't page-flip, perform deep modeset */
                grdrm_crtc_commit_deep(crtc, fb);
        }
}

static void grdrm_crtc_restore(grdrm_crtc *crtc) {
        struct drm_mode_crtc set_crtc = { .crtc_id = crtc->object.id };
        grdrm_card *card = crtc->object.card;
        int r;

        if (!crtc->old.set)
                return;

        set_crtc.set_connectors_ptr = PTR_TO_UINT64(crtc->old.connectors);
        set_crtc.count_connectors = crtc->old.n_connectors;
        set_crtc.fb_id = crtc->old.fb;
        set_crtc.x = crtc->old.fb_x;
        set_crtc.y = crtc->old.fb_y;
        set_crtc.gamma_size = crtc->old.gamma;
        set_crtc.mode_valid = crtc->old.mode_set;
        set_crtc.mode = crtc->old.mode;

        r = ioctl(card->fd, DRM_IOCTL_MODE_SETCRTC, &set_crtc);
        if (r < 0) {
                r = -errno;
                log_debug_errno(errno, "grdrm: %s: cannot restore crtc %" PRIu32 ": %m",
                                card->base.name, crtc->object.id);

                grdrm_card_async(card, r);
                return;
        }

        if (crtc->pipe) {
                ++crtc->pipe->counter;
                crtc->pipe->base.front = NULL;
                crtc->pipe->base.flipping = false;
        }

        log_debug("grdrm: %s: crtc %" PRIu32 " restored", card->base.name, crtc->object.id);
}

static void grdrm_crtc_flip_complete(grdrm_crtc *crtc, uint32_t counter, struct drm_event_vblank *event) {
        bool flipped = false;
        grdrm_pipe *pipe;
        size_t i;

        assert(crtc);
        assert(event);

        pipe = crtc->pipe;
        if (!pipe)
                return;

        /* We got a page-flip event. To be safe, we reset all FBs on the same
         * pipe that have smaller flipids than the flip we got as we know they
         * are executed in order. We need to do this to guarantee
         * queue-overflows or other missed events don't cause starvation.
         * Furthermore, if we find the exact FB this event is for, *and* this
         * is the most recent event, we mark it as front FB and raise a
         * frame event. */

        for (i = 0; i < pipe->base.max_fbs; ++i) {
                grdrm_fb *fb;

                if (!pipe->base.fbs[i])
                        continue;

                fb = fb_from_base(pipe->base.fbs[i]);
                if (counter != 0 && counter == pipe->counter && fb->flipid == counter) {
                        pipe->base.front = &fb->base;
                        fb->flipid = 0;
                        flipped = true;
                } else if (counter - fb->flipid < UINT16_MAX) {
                        fb->flipid = 0;
                }
        }

        if (flipped) {
                crtc->pipe->base.flipping = false;
                grdev_pipe_frame(&pipe->base);
        }
}

/*
 * Framebuffers
 */

static int grdrm_fb_new(grdrm_fb **out, grdrm_card *card, const struct drm_mode_modeinfo *mode) {
        _cleanup_(grdrm_fb_freep) grdrm_fb *fb = NULL;
        struct drm_mode_create_dumb create_dumb = { };
        struct drm_mode_map_dumb map_dumb = { };
        struct drm_mode_fb_cmd2 add_fb = { };
        unsigned int i;
        int r;

        assert_return(out, -EINVAL);
        assert_return(card, -EINVAL);

        fb = new0(grdrm_fb, 1);
        if (!fb)
                return -ENOMEM;

        /* TODO: we should choose a compatible format of the previous CRTC
         * setting to allow page-flip to it. Only choose fallback if the
         * previous setting was crap (non xrgb32'ish). */

        fb->card = card;
        fb->base.format = DRM_FORMAT_XRGB8888;
        fb->base.width = mode->hdisplay;
        fb->base.height = mode->vdisplay;

        for (i = 0; i < ELEMENTSOF(fb->base.maps); ++i)
                fb->base.maps[i] = MAP_FAILED;

        create_dumb.width = fb->base.width;
        create_dumb.height = fb->base.height;
        create_dumb.bpp = 32;

        r = ioctl(card->fd, DRM_IOCTL_MODE_CREATE_DUMB, &create_dumb);
        if (r < 0) {
                r = negative_errno();
                log_debug_errno(errno, "grdrm: %s: cannot create dumb buffer %" PRIu32 "x%" PRIu32": %m",
                                card->base.name, fb->base.width, fb->base.height);
                return r;
        }

        fb->handles[0] = create_dumb.handle;
        fb->base.strides[0] = create_dumb.pitch;
        fb->sizes[0] = create_dumb.size;

        map_dumb.handle = fb->handles[0];

        r = ioctl(card->fd, DRM_IOCTL_MODE_MAP_DUMB, &map_dumb);
        if (r < 0) {
                r = negative_errno();
                log_debug_errno(errno, "grdrm: %s: cannot map dumb buffer %" PRIu32 "x%" PRIu32": %m",
                                card->base.name, fb->base.width, fb->base.height);
                return r;
        }

        fb->base.maps[0] = mmap(0, fb->sizes[0], PROT_WRITE, MAP_SHARED, card->fd, map_dumb.offset);
        if (fb->base.maps[0] == MAP_FAILED) {
                r = negative_errno();
                log_debug_errno(errno, "grdrm: %s: cannot memory-map dumb buffer %" PRIu32 "x%" PRIu32": %m",
                                card->base.name, fb->base.width, fb->base.height);
                return r;
        }

        memzero(fb->base.maps[0], fb->sizes[0]);

        add_fb.width = fb->base.width;
        add_fb.height = fb->base.height;
        add_fb.pixel_format = fb->base.format;
        add_fb.flags = 0;
        memcpy(add_fb.handles, fb->handles, sizeof(fb->handles));
        memcpy(add_fb.pitches, fb->base.strides, sizeof(fb->base.strides));
        memcpy(add_fb.offsets, fb->offsets, sizeof(fb->offsets));

        r = ioctl(card->fd, DRM_IOCTL_MODE_ADDFB2, &add_fb);
        if (r < 0) {
                r = negative_errno();
                log_debug_errno(errno, "grdrm: %s: cannot add framebuffer %" PRIu32 "x%" PRIu32": %m",
                                card->base.name, fb->base.width, fb->base.height);
                return r;
        }

        fb->id = add_fb.fb_id;

        *out = fb;
        fb = NULL;
        return 0;
}

grdrm_fb *grdrm_fb_free(grdrm_fb *fb) {
        unsigned int i;
        int r;

        if (!fb)
                return NULL;

        assert(fb->card);

        if (fb->base.free_fn)
                fb->base.free_fn(fb->base.data.ptr);

        if (fb->id > 0 && fb->card->fd >= 0) {
                r = ioctl(fb->card->fd, DRM_IOCTL_MODE_RMFB, fb->id);
                if (r < 0)
                        log_debug_errno(errno, "grdrm: %s: cannot delete framebuffer %" PRIu32 ": %m",
                                        fb->card->base.name, fb->id);
        }

        for (i = 0; i < ELEMENTSOF(fb->handles); ++i) {
                struct drm_mode_destroy_dumb destroy_dumb = { };

                if (fb->base.maps[i] != MAP_FAILED)
                        munmap(fb->base.maps[i], fb->sizes[i]);

                if (fb->handles[i] > 0 && fb->card->fd >= 0) {
                        destroy_dumb.handle = fb->handles[i];
                        r = ioctl(fb->card->fd, DRM_IOCTL_MODE_DESTROY_DUMB, &destroy_dumb);
                        if (r < 0)
                                log_debug_errno(errno, "grdrm: %s: cannot destroy dumb-buffer %" PRIu32 ": %m",
                                                fb->card->base.name, fb->handles[i]);
                }
        }

        free(fb);

        return NULL;
}

/*
 * Pipes
 */

static void grdrm_pipe_name(char *out, grdrm_crtc *crtc) {
        /* @out must be at least of size GRDRM_PIPE_NAME_MAX */
        sprintf(out, "%s/%" PRIu32, crtc->object.card->base.name, crtc->object.id);
}

static int grdrm_pipe_new(grdrm_pipe **out, grdrm_crtc *crtc, struct drm_mode_modeinfo *mode, size_t n_fbs) {
        _cleanup_(grdev_pipe_freep) grdev_pipe *basepipe = NULL;
        grdrm_card *card = crtc->object.card;
        char name[GRDRM_PIPE_NAME_MAX];
        grdrm_pipe *pipe;
        int r;

        assert_return(crtc, -EINVAL);
        assert_return(grdev_is_drm_card(&card->base), -EINVAL);

        pipe = new0(grdrm_pipe, 1);
        if (!pipe)
                return -ENOMEM;

        basepipe = &pipe->base;
        pipe->base = GRDEV_PIPE_INIT(&grdrm_pipe_vtable, &card->base);
        pipe->crtc = crtc;
        pipe->base.width = mode->hdisplay;
        pipe->base.height = mode->vdisplay;
        pipe->base.vrefresh = mode->vrefresh ? : 25;

        grdrm_pipe_name(name, crtc);
        r = grdev_pipe_add(&pipe->base, name, n_fbs);
        if (r < 0)
                return r;

        if (out)
                *out = pipe;
        basepipe = NULL;
        return 0;
}

static void grdrm_pipe_free(grdev_pipe *basepipe) {
        grdrm_pipe *pipe = grdrm_pipe_from_base(basepipe);
        size_t i;

        assert(pipe->crtc);

        for (i = 0; i < pipe->base.max_fbs; ++i)
                if (pipe->base.fbs[i])
                        grdrm_fb_free(fb_from_base(pipe->base.fbs[i]));

        free(pipe);
}

static grdev_fb *grdrm_pipe_target(grdev_pipe *basepipe) {
        grdrm_fb *fb;
        size_t i;

        if (!basepipe->back) {
                for (i = 0; i < basepipe->max_fbs; ++i) {
                        if (!basepipe->fbs[i])
                                continue;

                        fb = fb_from_base(basepipe->fbs[i]);
                        if (&fb->base == basepipe->front)
                                continue;
                        if (basepipe->flipping && fb->flipid)
                                continue;

                        basepipe->back = &fb->base;
                        break;
                }
        }

        return basepipe->back;
}

static void grdrm_pipe_enable(grdev_pipe *basepipe) {
        grdrm_pipe *pipe = grdrm_pipe_from_base(basepipe);

        pipe->crtc->applied = false;
}

static void grdrm_pipe_disable(grdev_pipe *basepipe) {
        grdrm_pipe *pipe = grdrm_pipe_from_base(basepipe);

        pipe->crtc->applied = false;
}

static const grdev_pipe_vtable grdrm_pipe_vtable = {
        .free                   = grdrm_pipe_free,
        .target                 = grdrm_pipe_target,
        .enable                 = grdrm_pipe_enable,
        .disable                = grdrm_pipe_disable,
};

/*
 * Cards
 */

static void grdrm_name(char *out, dev_t devnum) {
        /* @out must be at least of size GRDRM_CARD_NAME_MAX */
        sprintf(out, "drm/%u:%u", major(devnum), minor(devnum));
}

static void grdrm_card_print(grdrm_card *card) {
        grdrm_object *object;
        grdrm_crtc *crtc;
        grdrm_encoder *encoder;
        grdrm_connector *connector;
        grdrm_plane *plane;
        Iterator iter;
        uint32_t i;
        char *p, *buf;

        log_debug("grdrm: %s: state dump", card->base.name);

        log_debug("  crtcs:");
        HASHMAP_FOREACH(object, card->object_map, iter) {
                if (object->type != GRDRM_TYPE_CRTC)
                        continue;

                crtc = crtc_from_object(object);
                log_debug("    (id: %u index: %d)", object->id, object->index);

                if (crtc->kern.mode_set)
                        log_debug("      mode: %dx%d", crtc->kern.mode.hdisplay, crtc->kern.mode.vdisplay);
                else
                        log_debug("      mode: <none>");
        }

        log_debug("  encoders:");
        HASHMAP_FOREACH(object, card->object_map, iter) {
                if (object->type != GRDRM_TYPE_ENCODER)
                        continue;

                encoder = encoder_from_object(object);
                log_debug("    (id: %u index: %d)", object->id, object->index);

                if (encoder->kern.used_crtc)
                        log_debug("      crtc: %u", encoder->kern.used_crtc);
                else
                        log_debug("      crtc: <none>");

                buf = malloc((DECIMAL_STR_MAX(uint32_t) + 1) * encoder->kern.n_crtcs + 1);
                if (buf) {
                        buf[0] = 0;
                        p = buf;

                        for (i = 0; i < encoder->kern.n_crtcs; ++i)
                                p += sprintf(p, " %" PRIu32, encoder->kern.crtcs[i]);

                        log_debug("      possible crtcs:%s", buf);
                        free(buf);
                }

                buf = malloc((DECIMAL_STR_MAX(uint32_t) + 1) * encoder->kern.n_clones + 1);
                if (buf) {
                        buf[0] = 0;
                        p = buf;

                        for (i = 0; i < encoder->kern.n_clones; ++i)
                                p += sprintf(p, " %" PRIu32, encoder->kern.clones[i]);

                        log_debug("      possible clones:%s", buf);
                        free(buf);
                }
        }

        log_debug("  connectors:");
        HASHMAP_FOREACH(object, card->object_map, iter) {
                if (object->type != GRDRM_TYPE_CONNECTOR)
                        continue;

                connector = connector_from_object(object);
                log_debug("    (id: %u index: %d)", object->id, object->index);
                log_debug("      type: %" PRIu32 "-%" PRIu32 " connection: %" PRIu32 " subpixel: %" PRIu32 " extents: %" PRIu32 "x%" PRIu32,
                          connector->kern.type, connector->kern.type_id, connector->kern.connection, connector->kern.subpixel,
                          connector->kern.mm_width, connector->kern.mm_height);

                if (connector->kern.used_encoder)
                        log_debug("      encoder: %" PRIu32, connector->kern.used_encoder);
                else
                        log_debug("      encoder: <none>");

                buf = malloc((DECIMAL_STR_MAX(uint32_t) + 1) * connector->kern.n_encoders + 1);
                if (buf) {
                        buf[0] = 0;
                        p = buf;

                        for (i = 0; i < connector->kern.n_encoders; ++i)
                                p += sprintf(p, " %" PRIu32, connector->kern.encoders[i]);

                        log_debug("      possible encoders:%s", buf);
                        free(buf);
                }

                for (i = 0; i < connector->kern.n_modes; ++i) {
                        struct drm_mode_modeinfo *mode = &connector->kern.modes[i];
                        log_debug("      mode: %" PRIu32 "x%" PRIu32, mode->hdisplay, mode->vdisplay);
                }
        }

        log_debug("  planes:");
        HASHMAP_FOREACH(object, card->object_map, iter) {
                if (object->type != GRDRM_TYPE_PLANE)
                        continue;

                plane = plane_from_object(object);
                log_debug("    (id: %u index: %d)", object->id, object->index);
                log_debug("      gamma-size: %" PRIu32, plane->kern.gamma_size);

                if (plane->kern.used_crtc)
                        log_debug("      crtc: %" PRIu32, plane->kern.used_crtc);
                else
                        log_debug("      crtc: <none>");

                buf = malloc((DECIMAL_STR_MAX(uint32_t) + 1) * plane->kern.n_crtcs + 1);
                if (buf) {
                        buf[0] = 0;
                        p = buf;

                        for (i = 0; i < plane->kern.n_crtcs; ++i)
                                p += sprintf(p, " %" PRIu32, plane->kern.crtcs[i]);

                        log_debug("      possible crtcs:%s", buf);
                        free(buf);
                }

                buf = malloc((DECIMAL_STR_MAX(unsigned int) + 3) * plane->kern.n_formats + 1);
                if (buf) {
                        buf[0] = 0;
                        p = buf;

                        for (i = 0; i < plane->kern.n_formats; ++i)
                                p += sprintf(p, " 0x%x", (unsigned int)plane->kern.formats[i]);

                        log_debug("      possible formats:%s", buf);
                        free(buf);
                }
        }
}

static int grdrm_card_resync(grdrm_card *card) {
        _cleanup_free_ uint32_t *crtc_ids = NULL, *encoder_ids = NULL, *connector_ids = NULL, *plane_ids = NULL;
        uint32_t allocated = 0;
        grdrm_object *object;
        Iterator iter;
        size_t tries;
        int r;

        assert(card);

        card->async_hotplug = false;
        allocated = 0;

        /* mark existing objects for possible removal */
        HASHMAP_FOREACH(object, card->object_map, iter)
                object->present = false;

        for (tries = 0; tries < GRDRM_MAX_TRIES; ++tries) {
                struct drm_mode_get_plane_res pres;
                struct drm_mode_card_res res;
                uint32_t i, max;

                if (allocated < card->max_ids) {
                        free(crtc_ids);
                        free(encoder_ids);
                        free(connector_ids);
                        free(plane_ids);
                        crtc_ids = new0(uint32_t, card->max_ids);
                        encoder_ids = new0(uint32_t, card->max_ids);
                        connector_ids = new0(uint32_t, card->max_ids);
                        plane_ids = new0(uint32_t, card->max_ids);

                        if (!crtc_ids || !encoder_ids || !connector_ids || !plane_ids)
                                return -ENOMEM;

                        allocated = card->max_ids;
                }

                zero(res);
                res.crtc_id_ptr = PTR_TO_UINT64(crtc_ids);
                res.connector_id_ptr = PTR_TO_UINT64(connector_ids);
                res.encoder_id_ptr = PTR_TO_UINT64(encoder_ids);
                res.count_crtcs = allocated;
                res.count_encoders = allocated;
                res.count_connectors = allocated;

                r = ioctl(card->fd, DRM_IOCTL_MODE_GETRESOURCES, &res);
                if (r < 0) {
                        r = -errno;
                        log_debug_errno(errno, "grdrm: %s: cannot retrieve drm resources: %m",
                                        card->base.name);
                        return r;
                }

                zero(pres);
                pres.plane_id_ptr = PTR_TO_UINT64(plane_ids);
                pres.count_planes = allocated;

                r = ioctl(card->fd, DRM_IOCTL_MODE_GETPLANERESOURCES, &pres);
                if (r < 0) {
                        r = -errno;
                        log_debug_errno(errno, "grdrm: %s: cannot retrieve drm plane-resources: %m",
                                        card->base.name);
                        return r;
                }

                max = MAX(MAX(res.count_crtcs, res.count_encoders),
                          MAX(res.count_connectors, pres.count_planes));
                if (max > allocated) {
                        uint32_t n;

                        n = ALIGN_POWER2(max);
                        if (!n || n > UINT16_MAX) {
                                log_debug("grdrm: %s: excessive DRM resource limit: %" PRIu32,
                                          card->base.name, max);
                                return -ERANGE;
                        }

                        /* retry with resized buffers */
                        card->max_ids = n;
                        continue;
                }

                /* mark available objects as present */

                for (i = 0; i < res.count_crtcs; ++i) {
                        object = grdrm_find_object(card, crtc_ids[i]);
                        if (object && object->type == GRDRM_TYPE_CRTC) {
                                object->present = true;
                                object->index = i;
                                crtc_ids[i] = 0;
                        }
                }

                for (i = 0; i < res.count_encoders; ++i) {
                        object = grdrm_find_object(card, encoder_ids[i]);
                        if (object && object->type == GRDRM_TYPE_ENCODER) {
                                object->present = true;
                                object->index = i;
                                encoder_ids[i] = 0;
                        }
                }

                for (i = 0; i < res.count_connectors; ++i) {
                        object = grdrm_find_object(card, connector_ids[i]);
                        if (object && object->type == GRDRM_TYPE_CONNECTOR) {
                                object->present = true;
                                object->index = i;
                                connector_ids[i] = 0;
                        }
                }

                for (i = 0; i < pres.count_planes; ++i) {
                        object = grdrm_find_object(card, plane_ids[i]);
                        if (object && object->type == GRDRM_TYPE_PLANE) {
                                object->present = true;
                                object->index = i;
                                plane_ids[i] = 0;
                        }
                }

                /* drop removed objects */

                HASHMAP_FOREACH(object, card->object_map, iter)
                        if (!object->present)
                                grdrm_object_free(object);

                /* add new objects */

                card->n_crtcs = res.count_crtcs;
                for (i = 0; i < res.count_crtcs; ++i) {
                        if (crtc_ids[i] < 1)
                                continue;

                        r = grdrm_crtc_new(NULL, card, crtc_ids[i], i);
                        if (r < 0)
                                return r;
                }

                card->n_encoders = res.count_encoders;
                for (i = 0; i < res.count_encoders; ++i) {
                        if (encoder_ids[i] < 1)
                                continue;

                        r = grdrm_encoder_new(NULL, card, encoder_ids[i], i);
                        if (r < 0)
                                return r;
                }

                card->n_connectors = res.count_connectors;
                for (i = 0; i < res.count_connectors; ++i) {
                        if (connector_ids[i] < 1)
                                continue;

                        r = grdrm_connector_new(NULL, card, connector_ids[i], i);
                        if (r < 0)
                                return r;
                }

                card->n_planes = pres.count_planes;
                for (i = 0; i < pres.count_planes; ++i) {
                        if (plane_ids[i] < 1)
                                continue;

                        r = grdrm_plane_new(NULL, card, plane_ids[i], i);
                        if (r < 0)
                                return r;
                }

                /* re-sync objects after object_map is synced */

                HASHMAP_FOREACH(object, card->object_map, iter) {
                        switch (object->type) {
                        case GRDRM_TYPE_CRTC:
                                r = grdrm_crtc_resync(crtc_from_object(object));
                                break;
                        case GRDRM_TYPE_ENCODER:
                                r = grdrm_encoder_resync(encoder_from_object(object));
                                break;
                        case GRDRM_TYPE_CONNECTOR:
                                r = grdrm_connector_resync(connector_from_object(object));
                                break;
                        case GRDRM_TYPE_PLANE:
                                r = grdrm_plane_resync(plane_from_object(object));
                                break;
                        default:
                                assert_not_reached("grdrm: invalid object type");
                                r = 0;
                        }

                        if (r < 0)
                                return r;

                        if (card->async_hotplug)
                                break;
                }

                /* if modeset objects change during sync, start over */
                if (card->async_hotplug) {
                        card->async_hotplug = false;
                        continue;
                }

                /* cache crtc/connector relationship */
                HASHMAP_FOREACH(object, card->object_map, iter) {
                        grdrm_connector *connector;
                        grdrm_encoder *encoder;
                        grdrm_crtc *crtc;

                        if (object->type != GRDRM_TYPE_CONNECTOR)
                                continue;

                        connector = connector_from_object(object);
                        if (connector->kern.connection != 1 || connector->kern.used_encoder < 1)
                                continue;

                        object = grdrm_find_object(card, connector->kern.used_encoder);
                        if (!object || object->type != GRDRM_TYPE_ENCODER)
                                continue;

                        encoder = encoder_from_object(object);
                        if (encoder->kern.used_crtc < 1)
                                continue;

                        object = grdrm_find_object(card, encoder->kern.used_crtc);
                        if (!object || object->type != GRDRM_TYPE_CRTC)
                                continue;

                        crtc = crtc_from_object(object);
                        assert(crtc->kern.n_used_connectors < crtc->kern.max_used_connectors);
                        crtc->kern.used_connectors[crtc->kern.n_used_connectors++] = connector->object.id;
                }

                /* cache old crtc settings for later restore */
                HASHMAP_FOREACH(object, card->object_map, iter) {
                        grdrm_crtc *crtc;

                        if (object->type != GRDRM_TYPE_CRTC)
                                continue;

                        crtc = crtc_from_object(object);

                        /* Save data if it is the first time we refresh the CRTC. This data can
                         * be used optionally to restore any previous configuration. For
                         * instance, it allows us to restore VT configurations after we close
                         * our session again. */
                        if (!crtc->old.set) {
                                crtc->old.fb = crtc->kern.used_fb;
                                crtc->old.fb_x = crtc->kern.fb_offset_x;
                                crtc->old.fb_y = crtc->kern.fb_offset_y;
                                crtc->old.gamma = crtc->kern.gamma_size;
                                crtc->old.n_connectors = crtc->kern.n_used_connectors;
                                if (crtc->old.n_connectors)
                                        memcpy(crtc->old.connectors, crtc->kern.used_connectors, sizeof(uint32_t) * crtc->old.n_connectors);
                                crtc->old.mode_set = crtc->kern.mode_set;
                                crtc->old.mode = crtc->kern.mode;
                                crtc->old.set = true;
                        }
                }

                /* everything synced */
                break;
        }

        if (tries >= GRDRM_MAX_TRIES) {
                /*
                 * Ugh! We were unable to sync the DRM card state due to heavy
                 * hotplugging. This should never happen, so print a debug
                 * message and bail out. The next uevent will trigger
                 * this again.
                 */

                log_debug("grdrm: %s: hotplug-storm when syncing card", card->base.name);
                return -EFAULT;
        }

        return 0;
}

static bool card_configure_crtc(grdrm_crtc *crtc, grdrm_connector *connector) {
        grdrm_card *card = crtc->object.card;
        grdrm_encoder *encoder;
        grdrm_object *object;
        uint32_t i, j;

        if (crtc->object.assigned || connector->object.assigned)
                return false;
        if (connector->kern.connection != 1)
                return false;

        for (i = 0; i < connector->kern.n_encoders; ++i) {
                object = grdrm_find_object(card, connector->kern.encoders[i]);
                if (!object || object->type != GRDRM_TYPE_ENCODER)
                        continue;

                encoder = encoder_from_object(object);
                for (j = 0; j < encoder->kern.n_crtcs; ++j) {
                        if (encoder->kern.crtcs[j] == crtc->object.id) {
                                grdrm_crtc_assign(crtc, connector);
                                return true;
                        }
                }
        }

        return false;
}

static void grdrm_card_configure(grdrm_card *card) {
        /*
         * Modeset Configuration
         * This is where we update our modeset configuration and assign
         * connectors to CRTCs. This means, each connector that we want to
         * enable needs a CRTC, disabled (or unavailable) connectors are left
         * alone in the dark. Once all CRTCs are assigned, the remaining CRTCs
         * are disabled.
         * Sounds trivial, but there're several caveats:
         *
         *   * Multiple connectors can be driven by the same CRTC. This is
         *     known as 'hardware clone mode'. Advantage over software clone
         *     mode is that only a single CRTC is needed to drive multiple
         *     displays. However, few hardware supports this and it's a huge
         *     headache to configure on dynamic demands. Therefore, we only
         *     support it if configured statically beforehand.
         *
         *   * CRTCs are not created equal. Some might be much more powerful
         *     than others, including more advanced plane support. So far, our
         *     CRTC selection is random. You need to supply static
         *     configuration if you want special setups. So far, there is no
         *     proper way to do advanced CRTC selection on dynamic demands. It
         *     is not really clear which demands require what CRTC, so, like
         *     everyone else, we do random CRTC selection unless explicitly
         *     states otherwise.
         *
         *   * Each Connector has a list of possible encoders that can drive
         *     it, and each encoder has a list of possible CRTCs. If this graph
         *     is a tree, assignment is trivial. However, if not, we cannot
         *     reliably decide on configurations beforehand. The encoder is
         *     always selected by the kernel, so we have to actually set a mode
         *     to know which encoder is used. There is no way to ask the kernel
         *     whether a given configuration is possible. This will change with
         *     atomic-modesetting, but until then, we keep our configurations
         *     simple and assume they work all just fine. If one fails
         *     unexpectedly, we print a warning and disable it.
         *
         * Configuring a card consists of several steps:
         *
         *  1) First of all, we apply any user-configuration. If a user wants
         *     a fixed configuration, we apply it and preserve it.
         *     So far, we don't support user configuration files, so this step
         *     is skipped.
         *
         *  2) Secondly, we need to apply any quirks from hwdb. Some hardware
         *     might only support limited configurations or require special
         *     CRTC/Connector mappings. We read this from hwdb and apply it, if
         *     present.
         *     So far, we don't support this as there is no known quirk, so
         *     this step is skipped.
         *
         *  3) As deep modesets are expensive, we try to avoid them if
         *     possible. Therefore, we read the current configuration from the
         *     kernel and try to preserve it, if compatible with our demands.
         *     If not, we break it and reassign it in a following step.
         *
         *  4) The main step involves configuring all remaining objects. By
         *     default, all available connectors are enabled, except for those
         *     disabled by user-configuration. We lookup a suitable CRTC for
         *     each connector and assign them. As there might be more
         *     connectors than CRTCs, we apply some ordering so users can
         *     select which connectors are more important right now.
         *     So far, we only apply the default ordering, more might be added
         *     in the future.
         */

        grdrm_object *object;
        grdrm_crtc *crtc;
        Iterator i, j;

        /* clear assignments */
        HASHMAP_FOREACH(object, card->object_map, i)
                object->assigned = false;

        /* preserve existing configurations */
        HASHMAP_FOREACH(object, card->object_map, i) {
                if (object->type != GRDRM_TYPE_CRTC || object->assigned)
                        continue;

                crtc = crtc_from_object(object);

                if (crtc->applied) {
                        /* If our mode is set, preserve it. If no connector is
                         * set, modeset either failed or the pipe is unused. In
                         * both cases, leave it alone. It might be tried again
                         * below in case there're remaining connectors.
                         * Otherwise, try restoring the assignments. If they
                         * are no longer valid, leave the pipe untouched. */

                        if (crtc->set.n_connectors < 1)
                                continue;

                        assert(crtc->set.n_connectors == 1);

                        object = grdrm_find_object(card, crtc->set.connectors[0]);
                        if (!object || object->type != GRDRM_TYPE_CONNECTOR)
                                continue;

                        card_configure_crtc(crtc, connector_from_object(object));
                } else if (crtc->kern.mode_set && crtc->kern.n_used_connectors != 1) {
                        /* If our mode is not set on the pipe, we know the kern
                         * information is valid. Try keeping it. If it's not
                         * possible, leave the pipe untouched for later
                         * assignements. */

                        object = grdrm_find_object(card, crtc->kern.used_connectors[0]);
                        if (!object || object->type != GRDRM_TYPE_CONNECTOR)
                                continue;

                        card_configure_crtc(crtc, connector_from_object(object));
                }
        }

        /* assign remaining objects */
        HASHMAP_FOREACH(object, card->object_map, i) {
                if (object->type != GRDRM_TYPE_CRTC || object->assigned)
                        continue;

                crtc = crtc_from_object(object);

                HASHMAP_FOREACH(object, card->object_map, j) {
                        if (object->type != GRDRM_TYPE_CONNECTOR)
                                continue;

                        if (card_configure_crtc(crtc, connector_from_object(object)))
                                break;
                }

                if (!crtc->object.assigned)
                        grdrm_crtc_assign(crtc, NULL);
        }

        /* expose configuration */
        HASHMAP_FOREACH(object, card->object_map, i) {
                if (object->type != GRDRM_TYPE_CRTC)
                        continue;

                grdrm_crtc_expose(crtc_from_object(object));
        }
}

static void grdrm_card_hotplug(grdrm_card *card) {
        int r;

        assert(card);

        if (!card->running)
                return;

        log_debug("grdrm: %s/%s: reconfigure card", card->base.session->name, card->base.name);

        card->ready = false;
        r = grdrm_card_resync(card);
        if (r < 0) {
                log_debug_errno(r, "grdrm: %s/%s: cannot re-sync card: %m",
                                card->base.session->name, card->base.name);
                return;
        }

        grdev_session_pin(card->base.session);

        /* debug statement to print card information */
        if (0)
                grdrm_card_print(card);

        grdrm_card_configure(card);
        card->ready = true;
        card->hotplug = false;

        grdev_session_unpin(card->base.session);
}

static int grdrm_card_io_fn(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        grdrm_card *card = userdata;
        struct drm_event_vblank *vblank;
        struct drm_event *event;
        uint32_t id, counter;
        grdrm_object *object;
        char buf[4096];
        size_t len;
        ssize_t l;

        if (revents & (EPOLLHUP | EPOLLERR)) {
                /* Immediately close device on HUP; no need to flush pending
                 * data.. there're no events we care about here. */
                log_debug("grdrm: %s/%s: HUP", card->base.session->name, card->base.name);
                grdrm_card_close(card);
                return 0;
        }

        if (revents & (EPOLLIN)) {
                l = read(card->fd, buf, sizeof(buf));
                if (l < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                return 0;

                        log_debug_errno(errno, "grdrm: %s/%s: read error: %m",
                                        card->base.session->name, card->base.name);
                        grdrm_card_close(card);
                        return 0;
                }

                for (len = l; len > 0; len -= event->length) {
                        event = (void*)buf;

                        if (len < sizeof(*event) || len < event->length) {
                                log_debug("grdrm: %s/%s: truncated event",
                                          card->base.session->name, card->base.name);
                                break;
                        }

                        switch (event->type) {
                        case DRM_EVENT_FLIP_COMPLETE:
                                vblank = (void*)event;
                                if (event->length < sizeof(*vblank)) {
                                        log_debug("grdrm: %s/%s: truncated vblank event",
                                                  card->base.session->name, card->base.name);
                                        break;
                                }

                                grdrm_decode_vblank_data(vblank->user_data, &id, &counter);
                                object = grdrm_find_object(card, id);
                                if (!object || object->type != GRDRM_TYPE_CRTC)
                                        break;

                                grdrm_crtc_flip_complete(crtc_from_object(object), counter, vblank);
                                break;
                        }
                }
        }

        return 0;
}

static int grdrm_card_add(grdrm_card *card, const char *name) {
        assert(card);
        assert(card->fd < 0);

        card->object_map = hashmap_new(&trivial_hash_ops);
        if (!card->object_map)
                return -ENOMEM;

        return grdev_card_add(&card->base, name);
}

static void grdrm_card_destroy(grdrm_card *card) {
        assert(card);
        assert(!card->running);
        assert(card->fd < 0);
        assert(hashmap_size(card->object_map) == 0);

        hashmap_free(card->object_map);
}

static void grdrm_card_commit(grdev_card *basecard) {
        grdrm_card *card = grdrm_card_from_base(basecard);
        grdrm_object *object;
        Iterator iter;

        HASHMAP_FOREACH(object, card->object_map, iter) {
                if (!card->ready)
                        break;

                if (object->type != GRDRM_TYPE_CRTC)
                        continue;

                grdrm_crtc_commit(crtc_from_object(object));
        }
}

static void grdrm_card_restore(grdev_card *basecard) {
        grdrm_card *card = grdrm_card_from_base(basecard);
        grdrm_object *object;
        Iterator iter;

        HASHMAP_FOREACH(object, card->object_map, iter) {
                if (!card->ready)
                        break;

                if (object->type != GRDRM_TYPE_CRTC)
                        continue;

                grdrm_crtc_restore(crtc_from_object(object));
        }
}

static void grdrm_card_enable(grdrm_card *card) {
        assert(card);

        if (card->fd < 0 || card->running)
                return;

        /* ignore cards without DUMB_BUFFER capability */
        if (!card->cap_dumb)
                return;

        assert(card->fd_src);

        log_debug("grdrm: %s/%s: enable", card->base.session->name, card->base.name);

        card->running = true;
        sd_event_source_set_enabled(card->fd_src, SD_EVENT_ON);
        grdrm_card_hotplug(card);
}

static void grdrm_card_disable(grdrm_card *card) {
        grdrm_object *object;
        Iterator iter;

        assert(card);

        if (card->fd < 0 || !card->running)
                return;

        assert(card->fd_src);

        log_debug("grdrm: %s/%s: disable", card->base.session->name, card->base.name);

        card->running = false;
        card->ready = false;
        sd_event_source_set_enabled(card->fd_src, SD_EVENT_OFF);

        /* stop all pipes */
        HASHMAP_FOREACH(object, card->object_map, iter) {
                grdrm_crtc *crtc;

                if (object->type != GRDRM_TYPE_CRTC)
                        continue;

                crtc = crtc_from_object(object);
                crtc->applied = false;
                if (crtc->pipe)
                        grdev_pipe_ready(&crtc->pipe->base, false);
        }
}

static int grdrm_card_open(grdrm_card *card, int dev_fd) {
        _cleanup_(grdev_session_unpinp) grdev_session *pin = NULL;
        _cleanup_close_ int fd = dev_fd;
        struct drm_get_cap cap;
        int r, flags;

        assert(card);
        assert(dev_fd >= 0);
        assert(card->fd != dev_fd);

        pin = grdev_session_pin(card->base.session);
        grdrm_card_close(card);

        log_debug("grdrm: %s/%s: open", card->base.session->name, card->base.name);

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = fd_cloexec(fd, true);
        if (r < 0)
                return r;

        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0)
                return -errno;
        if ((flags & O_ACCMODE) != O_RDWR)
                return -EACCES;

        r = sd_event_add_io(card->base.session->context->event,
                            &card->fd_src,
                            fd,
                            EPOLLHUP | EPOLLERR | EPOLLIN,
                            grdrm_card_io_fn,
                            card);
        if (r < 0)
                return r;

        sd_event_source_set_enabled(card->fd_src, SD_EVENT_OFF);

        card->hotplug = true;
        card->fd = fd;
        fd = -1;

        /* cache DUMB_BUFFER capability */
        cap.capability = DRM_CAP_DUMB_BUFFER;
        cap.value = 0;
        r = ioctl(card->fd, DRM_IOCTL_GET_CAP, &cap);
        card->cap_dumb = r >= 0 && cap.value;
        if (r < 0)
                log_debug_errno(r, "grdrm: %s/%s: cannot retrieve DUMB_BUFFER capability: %m",
                                card->base.session->name, card->base.name);
        else if (!card->cap_dumb)
                log_debug("grdrm: %s/%s: DUMB_BUFFER capability not supported",
                          card->base.session->name, card->base.name);

        /* cache TIMESTAMP_MONOTONIC capability */
        cap.capability = DRM_CAP_TIMESTAMP_MONOTONIC;
        cap.value = 0;
        r = ioctl(card->fd, DRM_IOCTL_GET_CAP, &cap);
        card->cap_monotonic = r >= 0 && cap.value;
        if (r < 0)
                log_debug_errno(r, "grdrm: %s/%s: cannot retrieve TIMESTAMP_MONOTONIC capability: %m",
                                card->base.session->name, card->base.name);
        else if (!card->cap_monotonic)
                log_debug("grdrm: %s/%s: TIMESTAMP_MONOTONIC is disabled globally, fix this NOW!",
                          card->base.session->name, card->base.name);

        return 0;
}

static void grdrm_card_close(grdrm_card *card) {
        grdrm_object *object;

        if (card->fd < 0)
                return;

        log_debug("grdrm: %s/%s: close", card->base.session->name, card->base.name);

        grdrm_card_disable(card);

        card->fd_src = sd_event_source_unref(card->fd_src);
        card->fd = safe_close(card->fd);

        grdev_session_pin(card->base.session);
        while ((object = hashmap_first(card->object_map)))
                grdrm_object_free(object);
        grdev_session_unpin(card->base.session);
}

static bool grdrm_card_async(grdrm_card *card, int r) {
        switch (r) {
        case -EACCES:
                /* If we get EACCES on runtime DRM calls, we lost DRM-Master
                 * (or we did something terribly wrong). Immediately disable
                 * the card, so we stop all pipes and wait to be activated
                 * again. */
                grdrm_card_disable(card);
                break;
        case -ENOENT:
                /* DRM objects can be hotplugged at any time. If an object is
                 * removed that we use, we remember that state so a following
                 * call can test for this.
                 * Note that we also get a uevent as followup, this will resync
                 * the whole device. */
                card->async_hotplug = true;
                break;
        }

        return !card->ready;
}

/*
 * Unmanaged Cards
 * The unmanaged DRM card opens the device node for a given DRM device
 * directly (/dev/dri/cardX) and thus needs sufficient privileges. It opens
 * the device only if we really require it and releases it as soon as we're
 * disabled or closed.
 * The unmanaged element can be used in all situations where you have direct
 * access to DRM device nodes. Unlike managed DRM elements, it can be used
 * outside of user sessions and in emergency situations where logind is not
 * available.
 */

static void unmanaged_card_enable(grdev_card *basecard) {
        unmanaged_card *cu = unmanaged_card_from_base(basecard);
        int r, fd;

        if (cu->card.fd < 0) {
                /* try open on activation if it failed during allocation */
                fd = open(cu->devnode, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
                if (fd < 0) {
                        /* not fatal; simply ignore the device */
                        log_debug_errno(errno, "grdrm: %s/%s: cannot open node %s: %m",
                                        basecard->session->name, basecard->name, cu->devnode);
                        return;
                }

                /* we might already be DRM-Master by open(); that's fine */

                r = grdrm_card_open(&cu->card, fd);
                if (r < 0) {
                        log_debug_errno(r, "grdrm: %s/%s: cannot open: %m",
                                        basecard->session->name, basecard->name);
                        return;
                }
        }

        r = ioctl(cu->card.fd, DRM_IOCTL_SET_MASTER, 0);
        if (r < 0) {
                log_debug_errno(errno, "grdrm: %s/%s: cannot acquire DRM-Master: %m",
                                basecard->session->name, basecard->name);
                return;
        }

        grdrm_card_enable(&cu->card);
}

static void unmanaged_card_disable(grdev_card *basecard) {
        unmanaged_card *cu = unmanaged_card_from_base(basecard);

        grdrm_card_disable(&cu->card);
}

static int unmanaged_card_new(grdev_card **out, grdev_session *session, struct udev_device *ud) {
        _cleanup_(grdev_card_freep) grdev_card *basecard = NULL;
        char name[GRDRM_CARD_NAME_MAX];
        unmanaged_card *cu;
        const char *devnode;
        dev_t devnum;
        int r, fd;

        assert_return(session, -EINVAL);
        assert_return(ud, -EINVAL);

        devnode = udev_device_get_devnode(ud);
        devnum = udev_device_get_devnum(ud);
        if (!devnode || devnum == 0)
                return -ENODEV;

        grdrm_name(name, devnum);

        cu = new0(unmanaged_card, 1);
        if (!cu)
                return -ENOMEM;

        basecard = &cu->card.base;
        cu->card = GRDRM_CARD_INIT(&unmanaged_card_vtable, session);

        cu->devnode = strdup(devnode);
        if (!cu->devnode)
                return -ENOMEM;

        r = grdrm_card_add(&cu->card, name);
        if (r < 0)
                return r;

        /* try to open but ignore errors */
        fd = open(cu->devnode, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) {
                /* not fatal; allow uaccess based control on activation */
                log_debug_errno(errno, "grdrm: %s/%s: cannot open node %s: %m",
                                basecard->session->name, basecard->name, cu->devnode);
        } else {
                /* We might get DRM-Master implicitly on open(); drop it immediately
                 * so we acquire it only once we're actually enabled. We don't
                 * really care whether this call fails or not, but lets log any
                 * weird errors, anyway. */
                r = ioctl(fd, DRM_IOCTL_DROP_MASTER, 0);
                if (r < 0 && errno != EACCES && errno != EINVAL)
                        log_debug_errno(errno, "grdrm: %s/%s: cannot drop DRM-Master: %m",
                                        basecard->session->name, basecard->name);

                r = grdrm_card_open(&cu->card, fd);
                if (r < 0)
                        log_debug_errno(r, "grdrm: %s/%s: cannot open: %m",
                                        basecard->session->name, basecard->name);
        }

        if (out)
                *out = basecard;
        basecard = NULL;
        return 0;
}

static void unmanaged_card_free(grdev_card *basecard) {
        unmanaged_card *cu = unmanaged_card_from_base(basecard);

        assert(!basecard->enabled);

        grdrm_card_close(&cu->card);
        grdrm_card_destroy(&cu->card);
        free(cu->devnode);
        free(cu);
}

static const grdev_card_vtable unmanaged_card_vtable = {
        .free                   = unmanaged_card_free,
        .enable                 = unmanaged_card_enable,
        .disable                = unmanaged_card_disable,
        .commit                 = grdrm_card_commit,
        .restore                = grdrm_card_restore,
};

/*
 * Managed Cards
 * The managed DRM card uses systemd-logind to acquire DRM devices. This
 * means, we do not open the device node /dev/dri/cardX directly. Instead,
 * logind passes us a file-descriptor whenever our session is activated. Thus,
 * we don't need access to the device node directly.
 * Furthermore, whenever the session is put asleep, logind revokes the
 * file-descriptor so we loose access to the device.
 * Managed DRM cards should be preferred over unmanaged DRM cards whenever
 * you run inside a user session with exclusive device access.
 */

static void managed_card_enable(grdev_card *card) {
        managed_card *cm = managed_card_from_base(card);

        /* If the device is manually re-enabled, we try to resume our card
         * management. Note that we have no control over DRM-Master and the fd,
         * so we have to take over the state from the last logind event. */

        if (cm->master)
                grdrm_card_enable(&cm->card);
}

static void managed_card_disable(grdev_card *card) {
        managed_card *cm = managed_card_from_base(card);

        /* If the device is manually disabled, we keep the FD but put our card
         * management asleep. This way, we can wake up at any time, but don't
         * touch the device while asleep. */

        grdrm_card_disable(&cm->card);
}

static int managed_card_pause_device_fn(sd_bus_message *signal,
                                        void *userdata,
                                        sd_bus_error *ret_error) {
        managed_card *cm = userdata;
        grdev_session *session = cm->card.base.session;
        uint32_t major, minor;
        const char *mode;
        int r;

        /*
         * We get PauseDevice() signals from logind whenever a device we
         * requested was, or is about to be, paused. Arguments are major/minor
         * number of the device and the mode of the operation.
         * In case the event is not about our device, we ignore it. Otherwise,
         * we treat it as asynchronous DRM-DROP-MASTER. Note that we might have
         * already handled an EACCES error from a modeset ioctl, in which case
         * we already disabled the device.
         *
         * @mode can be one of the following:
         *   "pause": The device is about to be paused. We must react
         *            immediately and respond with PauseDeviceComplete(). Once
         *            we replied, logind will pause the device. Note that
         *            logind might apply any kind of timeout and force pause
         *            the device if we don't respond in a timely manner. In
         *            this case, we will receive a second PauseDevice event
         *            with @mode set to "force" (or similar).
         *   "force": The device was disabled forecfully by logind. DRM-Master
         *            was already dropped. This is just an asynchronous
         *            notification so we can put the device asleep (in case
         *            we didn't already notice the dropped DRM-Master).
         *    "gone": This is like "force" but is sent if the device was
         *            paused due to a device-removal event.
         *
         * We always handle PauseDevice signals as "force" as we properly
         * support asynchronously dropping DRM-Master, anyway. But in case
         * logind sent mode "pause", we also call PauseDeviceComplete() to
         * immediately acknowledge the request.
         */

        r = sd_bus_message_read(signal, "uus", &major, &minor, &mode);
        if (r < 0) {
                log_debug("grdrm: %s/%s: erroneous PauseDevice signal",
                          session->name, cm->card.base.name);
                return 0;
        }

        /* not our device? */
        if (makedev(major, minor) != cm->devnum)
                return 0;

        cm->master = false;
        grdrm_card_disable(&cm->card);

        if (streq(mode, "pause")) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;

                /*
                 * Sending PauseDeviceComplete() is racy if logind triggers the
                 * timeout. That is, if we take too long and logind pauses the
                 * device by sending a forced PauseDevice, our
                 * PauseDeviceComplete call will be stray. That's fine, though.
                 * logind ignores such stray calls. Only if logind also sent a
                 * further PauseDevice() signal, it might match our call
                 * incorrectly to the newer PauseDevice(). That's fine, too, as
                 * we handle that event asynchronously, anyway. Therefore,
                 * whatever happens, we're fine. Yay!
                 */

                r = sd_bus_message_new_method_call(session->context->sysbus,
                                                   &m,
                                                   "org.freedesktop.login1",
                                                   session->path,
                                                   "org.freedesktop.login1.Session",
                                                   "PauseDeviceComplete");
                if (r >= 0) {
                        r = sd_bus_message_append(m, "uu", major, minor);
                        if (r >= 0)
                                r = sd_bus_send(session->context->sysbus, m, NULL);
                }

                if (r < 0)
                        log_debug_errno(r, "grdrm: %s/%s: cannot send PauseDeviceComplete: %m",
                                        session->name, cm->card.base.name);
        }

        return 0;
}

static int managed_card_resume_device_fn(sd_bus_message *signal,
                                         void *userdata,
                                         sd_bus_error *ret_error) {
        managed_card *cm = userdata;
        grdev_session *session = cm->card.base.session;
        uint32_t major, minor;
        int r, fd;

        /*
         * We get ResumeDevice signals whenever logind resumed a previously
         * paused device. The arguments contain the major/minor number of the
         * related device and a new file-descriptor for the freshly opened
         * device-node.
         * If the signal is not about our device, we simply ignore it.
         * Otherwise, we immediately resume the device. Note that we drop the
         * new file-descriptor as we already have one from TakeDevice(). logind
         * preserves the file-context across pause/resume for DRM but only
         * drops/acquires DRM-Master accordingly. This way, our context (like
         * DRM-FBs and BOs) is preserved.
         */

        r = sd_bus_message_read(signal, "uuh", &major, &minor, &fd);
        if (r < 0) {
                log_debug("grdrm: %s/%s: erroneous ResumeDevice signal",
                          session->name, cm->card.base.name);
                return 0;
        }

        /* not our device? */
        if (makedev(major, minor) != cm->devnum)
                return 0;

        if (cm->card.fd < 0) {
                /* This shouldn't happen. We should already own an FD from
                 * TakeDevice(). However, lets be safe and use this FD in case
                 * we really don't have one. There is no harm in doing this
                 * and our code works fine this way. */
                fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                if (fd < 0) {
                        log_debug_errno(errno, "grdrm: %s/%s: cannot duplicate fd: %m",
                                        session->name, cm->card.base.name);
                        return 0;
                }

                r = grdrm_card_open(&cm->card, fd);
                if (r < 0) {
                        log_debug_errno(r, "grdrm: %s/%s: cannot open: %m",
                                        session->name, cm->card.base.name);
                        return 0;
                }
        }

        cm->master = true;
        if (cm->card.base.enabled)
                grdrm_card_enable(&cm->card);

        return 0;
}

static int managed_card_setup_bus(managed_card *cm) {
        grdev_session *session = cm->card.base.session;
        _cleanup_free_ char *match = NULL;
        int r;

        match = strjoin("type='signal',"
                        "sender='org.freedesktop.login1',"
                        "interface='org.freedesktop.login1.Session',"
                        "member='PauseDevice',"
                        "path='", session->path, "'",
                        NULL);
        if (!match)
                return -ENOMEM;

        r = sd_bus_add_match(session->context->sysbus,
                             &cm->slot_pause_device,
                             match,
                             managed_card_pause_device_fn,
                             cm);
        if (r < 0)
                return r;

        free(match);
        match = strjoin("type='signal',"
                        "sender='org.freedesktop.login1',"
                        "interface='org.freedesktop.login1.Session',"
                        "member='ResumeDevice',"
                        "path='", session->path, "'",
                        NULL);
        if (!match)
                return -ENOMEM;

        r = sd_bus_add_match(session->context->sysbus,
                             &cm->slot_resume_device,
                             match,
                             managed_card_resume_device_fn,
                             cm);
        if (r < 0)
                return r;

        return 0;
}

static int managed_card_take_device_fn(sd_bus_message *reply,
                                       void *userdata,
                                       sd_bus_error *ret_error) {
        managed_card *cm = userdata;
        grdev_session *session = cm->card.base.session;
        int r, paused, fd;

        cm->slot_take_device = sd_bus_slot_unref(cm->slot_take_device);

        if (sd_bus_message_is_method_error(reply, NULL)) {
                const sd_bus_error *error = sd_bus_message_get_error(reply);

                log_debug("grdrm: %s/%s: TakeDevice failed: %s: %s",
                          session->name, cm->card.base.name, error->name, error->message);
                return 0;
        }

        cm->acquired = true;

        r = sd_bus_message_read(reply, "hb", &fd, &paused);
        if (r < 0) {
                log_debug("grdrm: %s/%s: erroneous TakeDevice reply",
                          session->name, cm->card.base.name);
                return 0;
        }

        fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd < 0) {
                log_debug_errno(errno, "grdrm: %s/%s: cannot duplicate fd: %m",
                                session->name, cm->card.base.name);
                return 0;
        }

        r = grdrm_card_open(&cm->card, fd);
        if (r < 0) {
                log_debug_errno(r, "grdrm: %s/%s: cannot open: %m",
                                session->name, cm->card.base.name);
                return 0;
        }

        if (!paused && cm->card.base.enabled)
                grdrm_card_enable(&cm->card);

        return 0;
}

static void managed_card_take_device(managed_card *cm) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        grdev_session *session = cm->card.base.session;
        int r;

        r = sd_bus_message_new_method_call(session->context->sysbus,
                                           &m,
                                           "org.freedesktop.login1",
                                           session->path,
                                           "org.freedesktop.login1.Session",
                                           "TakeDevice");
        if (r < 0)
                goto error;

        r = sd_bus_message_append(m, "uu", major(cm->devnum), minor(cm->devnum));
        if (r < 0)
                goto error;

        r = sd_bus_call_async(session->context->sysbus,
                              &cm->slot_take_device,
                              m,
                              managed_card_take_device_fn,
                              cm,
                              0);
        if (r < 0)
                goto error;

        cm->requested = true;
        return;

error:
        log_debug_errno(r, "grdrm: %s/%s: cannot send TakeDevice request: %m",
                        session->name, cm->card.base.name);
}

static void managed_card_release_device(managed_card *cm) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        grdev_session *session = cm->card.base.session;
        int r;

        /*
         * If TakeDevice() is pending or was successful, make sure to
         * release the device again. We don't care for return-values,
         * so send it without waiting or callbacks.
         * If a failed TakeDevice() is pending, but someone else took
         * the device on the same bus-connection, we might incorrectly
         * release their device. This is an unlikely race, though.
         * Furthermore, you really shouldn't have two users of the
         * controller-API on the same session, on the same devices, *AND* on
         * the same bus-connection. So we don't care for that race..
         */

        grdrm_card_close(&cm->card);
        cm->requested = false;

        if (!cm->acquired && !cm->slot_take_device)
                return;

        cm->slot_take_device = sd_bus_slot_unref(cm->slot_take_device);
        cm->acquired = false;

        r = sd_bus_message_new_method_call(session->context->sysbus,
                                           &m,
                                           "org.freedesktop.login1",
                                           session->path,
                                           "org.freedesktop.login1.Session",
                                           "ReleaseDevice");
        if (r >= 0) {
                r = sd_bus_message_append(m, "uu", major(cm->devnum), minor(cm->devnum));
                if (r >= 0)
                        r = sd_bus_send(session->context->sysbus, m, NULL);
        }

        if (r < 0 && r != -ENOTCONN)
                log_debug_errno(r, "grdrm: %s/%s: cannot send ReleaseDevice: %m",
                                session->name, cm->card.base.name);
}

static int managed_card_new(grdev_card **out, grdev_session *session, struct udev_device *ud) {
        _cleanup_(grdev_card_freep) grdev_card *basecard = NULL;
        char name[GRDRM_CARD_NAME_MAX];
        managed_card *cm;
        dev_t devnum;
        int r;

        assert_return(session, -EINVAL);
        assert_return(session->managed, -EINVAL);
        assert_return(session->context->sysbus, -EINVAL);
        assert_return(ud, -EINVAL);

        devnum = udev_device_get_devnum(ud);
        if (devnum == 0)
                return -ENODEV;

        grdrm_name(name, devnum);

        cm = new0(managed_card, 1);
        if (!cm)
                return -ENOMEM;

        basecard = &cm->card.base;
        cm->card = GRDRM_CARD_INIT(&managed_card_vtable, session);
        cm->devnum = devnum;

        r = managed_card_setup_bus(cm);
        if (r < 0)
                return r;

        r = grdrm_card_add(&cm->card, name);
        if (r < 0)
                return r;

        managed_card_take_device(cm);

        if (out)
                *out = basecard;
        basecard = NULL;
        return 0;
}

static void managed_card_free(grdev_card *basecard) {
        managed_card *cm = managed_card_from_base(basecard);

        assert(!basecard->enabled);

        managed_card_release_device(cm);
        cm->slot_resume_device = sd_bus_slot_unref(cm->slot_resume_device);
        cm->slot_pause_device = sd_bus_slot_unref(cm->slot_pause_device);
        grdrm_card_destroy(&cm->card);
        free(cm);
}

static const grdev_card_vtable managed_card_vtable = {
        .free                   = managed_card_free,
        .enable                 = managed_card_enable,
        .disable                = managed_card_disable,
        .commit                 = grdrm_card_commit,
        .restore                = grdrm_card_restore,
};

/*
 * Generic Constructor
 * Instead of relying on the caller to choose between managed and unmanaged
 * DRM devices, the grdev_drm_new() constructor does that for you (by
 * looking at session->managed).
 */

bool grdev_is_drm_card(grdev_card *basecard) {
        return basecard && (basecard->vtable == &unmanaged_card_vtable ||
                            basecard->vtable == &managed_card_vtable);
}

grdev_card *grdev_find_drm_card(grdev_session *session, dev_t devnum) {
        char name[GRDRM_CARD_NAME_MAX];

        assert_return(session, NULL);
        assert_return(devnum != 0, NULL);

        grdrm_name(name, devnum);
        return grdev_find_card(session, name);
}

int grdev_drm_card_new(grdev_card **out, grdev_session *session, struct udev_device *ud) {
        assert_return(session, -EINVAL);
        assert_return(ud, -EINVAL);

        return session->managed ? managed_card_new(out, session, ud) : unmanaged_card_new(out, session, ud);
}

void grdev_drm_card_hotplug(grdev_card *basecard, struct udev_device *ud) {
        const char *p, *action;
        grdrm_card *card;
        dev_t devnum;

        assert(basecard);
        assert(grdev_is_drm_card(basecard));
        assert(ud);

        card = grdrm_card_from_base(basecard);

        action = udev_device_get_action(ud);
        if (!action || streq(action, "add") || streq(action, "remove")) {
                /* If we get add/remove events on DRM nodes without devnum, we
                 * got hotplugged DRM objects so refresh the device. */
                devnum = udev_device_get_devnum(ud);
                if (devnum == 0) {
                        card->hotplug = true;
                        grdrm_card_hotplug(card);
                }
        } else if (streq_ptr(action, "change")) {
                /* A change event with HOTPLUG=1 is sent whenever a connector
                 * changed state. Refresh the device to update our state. */
                p = udev_device_get_property_value(ud, "HOTPLUG");
                if (streq_ptr(p, "1")) {
                        card->hotplug = true;
                        grdrm_card_hotplug(card);
                }
        }
}
