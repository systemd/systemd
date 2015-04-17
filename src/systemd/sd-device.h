/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosddevicehfoo
#define foosddevicehfoo

/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>
  Copyright 2014-2015 Tom Gundersen <teg@jklm.no>

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

#include <sys/types.h>
#include <stdint.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_device sd_device;
typedef struct sd_device_enumerator sd_device_enumerator;

/* device */

sd_device *sd_device_ref(sd_device *device);
sd_device *sd_device_unref(sd_device *device);

int sd_device_new_from_syspath(sd_device **ret, const char *syspath);
int sd_device_new_from_devnum(sd_device **ret, char type, dev_t devnum);
int sd_device_new_from_subsystem_sysname(sd_device **ret, const char *subsystem, const char *sysname);
int sd_device_new_from_device_id(sd_device **ret, const char *id);

int sd_device_get_parent(sd_device *child, sd_device **ret);
int sd_device_get_parent_with_subsystem_devtype(sd_device *child, const char *subsystem, const char *devtype, sd_device **ret);

int sd_device_get_syspath(sd_device *device, const char **ret);
int sd_device_get_subsystem(sd_device *device, const char **ret);
int sd_device_get_devtype(sd_device *device, const char **ret);
int sd_device_get_devnum(sd_device *device, dev_t *devnum);
int sd_device_get_ifindex(sd_device *device, int *ifindex);
int sd_device_get_driver(sd_device *device, const char **ret);
int sd_device_get_devpath(sd_device *device, const char **ret);
int sd_device_get_devname(sd_device *device, const char **ret);
int sd_device_get_sysname(sd_device *device, const char **ret);
int sd_device_get_sysnum(sd_device *device, const char **ret);

int sd_device_get_is_initialized(sd_device *device, int *initialized);
int sd_device_get_usec_since_initialized(sd_device *device, uint64_t *usec);

const char *sd_device_get_tag_first(sd_device *device);
const char *sd_device_get_tag_next(sd_device *device);
const char *sd_device_get_devlink_first(sd_device *device);
const char *sd_device_get_devlink_next(sd_device *device);
const char *sd_device_get_property_first(sd_device *device, const char **value);
const char *sd_device_get_property_next(sd_device *device, const char **value);
const char *sd_device_get_sysattr_first(sd_device *device);
const char *sd_device_get_sysattr_next(sd_device *device);

int sd_device_has_tag(sd_device *device, const char *tag);
int sd_device_get_property_value(sd_device *device, const char *key, const char **value);
int sd_device_get_sysattr_value(sd_device *device, const char *sysattr, const char **_value);

int sd_device_set_sysattr_value(sd_device *device, const char *sysattr, char *value);

/* device enumerator */

int sd_device_enumerator_new(sd_device_enumerator **ret);
sd_device_enumerator *sd_device_enumerator_ref(sd_device_enumerator *enumerator);
sd_device_enumerator *sd_device_enumerator_unref(sd_device_enumerator *enumerator);

sd_device *sd_device_enumerator_get_device_first(sd_device_enumerator *enumerator);
sd_device *sd_device_enumerator_get_device_next(sd_device_enumerator *enumerator);
sd_device *sd_device_enumerator_get_subsystem_first(sd_device_enumerator *enumerator);
sd_device *sd_device_enumerator_get_subsystem_next(sd_device_enumerator *enumerator);

int sd_device_enumerator_add_match_subsystem(sd_device_enumerator *enumerator, const char *subsystem, int match);
int sd_device_enumerator_add_match_sysattr(sd_device_enumerator *enumerator, const char *sysattr, const char *value, int match);
int sd_device_enumerator_add_match_property(sd_device_enumerator *enumerator, const char *property, const char *value);
int sd_device_enumerator_add_match_sysname(sd_device_enumerator *enumerator, const char *sysname);
int sd_device_enumerator_add_match_tag(sd_device_enumerator *enumerator, const char *tag);
int sd_device_enumerator_add_match_parent(sd_device_enumerator *enumerator, sd_device *parent);
int sd_device_enumerator_allow_uninitialized(sd_device_enumerator *enumerator);

_SD_END_DECLARATIONS;

#endif
