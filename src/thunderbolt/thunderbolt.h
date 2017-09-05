#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Christian J. Kellner

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

#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
#include <sys/types.h>

#include "libudev.h"
#include "macro.h"

#define FORMAT_SECURITY_MAX 2 /* one digit plus nul */
#define HEX_BYTES 3           /* xx plus nul */
#define KEY_BYTES 32
#define KEY_CHARS 64          /* KEY_BYTES hex encoded */


/* With the exception of AUTH_MISSING (-1) the following values
 * corresponds to sysfs 'authorized' value. */
typedef enum {
        AUTH_MISSING = -1,
        AUTH_NEEDED  = 0,
        AUTH_USER    = 1,
        AUTH_KEY     = 2,
} AuthLevel;
#define auth_level_can_authorize(lv) (lv == AUTH_USER || lv == AUTH_KEY)

typedef enum {
        SECURITY_NONE    = 0,
        SECURITY_USER    = 1,
        SECURITY_SECURE  = 2,
        SECURITY_DPONLY  = 3,
        _SECURITY_MAX,
        _SECURITY_INVALID = -1,
} SecurityLevel;

SecurityLevel security_from_string(const char *l) _pure_;
const char *security_to_string(SecurityLevel l) _pure_;

typedef enum  {
        STORE_NONE    = -1,
        STORE_DEFAULT = 0,
        STORE_EFIVARS,
        STORE_FSDB,
} Store;

typedef struct Auth {
        int level;
        char *key;
        Store store;
} Auth;
#define AUTH_INITIALIZER {-1, NULL, -1}

void auth_reset(Auth *a);
#define _cleanup_auth_reset_ _cleanup_(auth_reset)
void auth_generate_key_string(Auth *a);

/* Device related functions */
typedef struct {

        struct udev_device *udev;
        DIR *devdir;

        char *uuid;
        AuthLevel authorized;

        char *name;
        char *vendor;

} TbDevice;

void tb_device_free(TbDevice **device);
#define _cleanup_tb_device_free_ _cleanup_(tb_device_free)

int tb_device_new_from_udev(struct udev_device *udev, TbDevice **ret);
int tb_device_new_from_syspath(struct udev *udev, const char *path, TbDevice **d);
int tb_device_authorize(TbDevice *dev, Auth *auth);
int tb_device_compare(const void *ia, const void *ib);
SecurityLevel tb_device_get_security_level(TbDevice *device);
bool tb_device_is_online(TbDevice *dev);

typedef struct {
        unsigned n;
        unsigned a;

        TbDevice **devices;
} TbDeviceVec;

void tb_device_vec_free(TbDeviceVec **v);
#define _cleanup_tb_device_vec_free_ _cleanup_(tb_device_vec_free)

TbDeviceVec *tb_device_vec_ensure_allocated(TbDeviceVec **v);
bool tb_device_vec_contains_uuid(TbDeviceVec *v, const char *uuid);
void tb_device_vec_push_back(TbDeviceVec *v, TbDevice *d);
void tb_device_vec_sort(TbDeviceVec *v);

static inline TbDevice *tb_device_vec_at(TbDeviceVec *v, unsigned i) {
        assert(v);
        assert(i < v->n);

        return v->devices[i];
}

/* Store related functions */
#define TB_STORE_PATH "/etc/thunderbolt"

typedef struct {
        char *path;
        Store store;
} TbStore;

void tb_store_free(TbStore **s);

#define _cleanup_tb_store_free_ _cleanup_(tb_store_free)

int tb_store_new(TbStore **ret);
int tb_store_list_ids(TbStore *store, char ***ret);
bool tb_store_have_device(TbStore *store, const char *uuid);
int tb_store_device_load(TbStore *store, const char *uuid, TbDevice **device);
int tb_store_load_missing(TbStore *store, TbDeviceVec **devices);
int store_get_auth(TbStore *store, const char *uuid, Auth *ret);
int tb_store_remove_auth(TbStore *store, const char *uuid);
int tb_store_remove_device(TbStore *store, const char *uuid);
int store_put_device(TbStore *store, TbDevice *device, Auth *auth);
