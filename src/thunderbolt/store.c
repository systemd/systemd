#include "thunderbolt.h"

#include <linux/fs.h>

#include "conf-parser.h"
#include "chattr-util.h"
#include "dirent-util.h"
#include "efivars.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fileio.h"
#include "hash-funcs.h"
#include "io-util.h"
#include "locale-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "random-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "terminal-util.h"
#include "udev-util.h"
#include "umask-util.h"
#include "util.h"


void tb_store_free(TbStore **store) {
        TbStore *s;

        if (!store || !*store)
                return;

        s = *store;

        free(s->path);
        free(s);
        *store = NULL;
}

int tb_store_new(TbStore **ret) {
        _cleanup_tb_store_free_ TbStore *s = NULL;
        const char *val;

        s = new0(TbStore, 1);
        if (!s)
                return -ENOMEM;

        val = getenv("SYSTEMD_THUNDERBOLT_DB_PATH");

        if (val)
                s->path = strdup(val);
        else
                s->path = strdup(TB_STORE_PATH);

        val = getenv("SYSTEMD_THUNDERBOLT_DB_STORE");
        if (val) {
                if (streq(val, "efivars")) {
                        s->store = STORE_EFIVARS;
                        if (!is_efi_boot())
                                return -ENOTSUP;
                } else if (streq(val, "fsdb")) {
                        s->store = STORE_FSDB;
                } else {
                        return -ENOTSUP;
                }
        } else if (is_efi_boot()) {
                s->store = STORE_EFIVARS;
        } else {
                s->store = STORE_FSDB;
        }

        *ret = s;
        s = NULL;

        return 0;
}


static int tb_store_parse_device(TbStore *store, TbDevice *device) {
        const ConfigTableItem items[] = {
                { "device", "name",    config_parse_string,  0, &device->name    },
                { "device", "vendor",  config_parse_string,  0, &device->vendor  },
                {}
        };
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -1;
        struct stat st;
        char *path;
        int r;

        assert(device);
        assert(device->uuid);

        path = strjoina(store->path, "/devices/", device->uuid);

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;
        if (fstat(fd, &st) < 0)
                return -errno;
        if (S_ISDIR(st.st_mode))
                return -EISDIR;
        if (!S_ISREG(st.st_mode))
                return -ENOTTY;

        f = fdopen(fd, "re");
        if (f == NULL)
                return -errno;

        r = config_parse(NULL, path, f,
                         NULL,
                         config_item_table_lookup, items,
                         true, true, false, device);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse %s: %m", device->uuid);

        return 0;
}

int tb_store_device_load(TbStore *store, const char *uuid, TbDevice **device) {
        TbDevice *d = NULL;
        int r;

        assert(store);
        assert(device);
        assert(uuid);

        d = new0(TbDevice, 1);
        if (!d) {
                r = -ENOMEM;
                goto out;
        }

        d->uuid = strdup(uuid);
        if (d->uuid == NULL) {
                r = -ENOMEM;
                tb_device_free(&d);
                goto out;
        }

        r = tb_store_parse_device(store, d);
        if (r < 0) {
                tb_device_free(&d);
        }

 out:
        *device = d;
        return r;
}


static int store_efivars_get_auth(const char *uuid, Auth *ret) {
        _cleanup_free_ void *var = NULL;
        sd_id128_t id;
        size_t l;
        int r;

        assert(ret);
        assert(uuid);

        if (sd_id128_from_string(uuid, &id) < 0) {
                return -EINVAL;
        }

        r = efi_get_variable(id, "Thunderbolt", NULL, &var, &l);
        if (r < 0)
                return r;

        ret->store = STORE_EFIVARS;
        if (l == 1) {
                return safe_atoi(var, &ret->level);
        } else if (l == KEY_CHARS) {
                ret->level = AUTH_KEY;
                ret->key = (char *) var;
                var = NULL;
                return 0;
        }

        /* should not happen, because only we write it */
        return -EIO;
}

int store_get_auth(TbStore *store, const char *uuid, Auth *ret) {
        _cleanup_free_ char *p = NULL;
        struct stat st;
        char *path;
        int r;

        if (in_initrd())
                return store_efivars_get_auth(uuid, ret);

        path = strjoina(store->path, "/authorization/", uuid);

        r = lstat(path, &st);
        if (r < 0 && errno == ENOENT) {
                ret->level = AUTH_MISSING;
                return 0;
        }
        if (r < 0)
                return -errno;
        if (S_ISREG(st.st_mode)) {
                _cleanup_free_ char *l = NULL;

                r = read_one_line_file(path, &l);
                if (r < 0)
                        return r;

                ret->store = STORE_FSDB;
                if (strlen(l) == KEY_CHARS) {
                        ret->level = AUTH_KEY;
                        ret->key = l;
                        l = NULL;
                } else {
                        ret->key = NULL;
                        r = safe_atoi(l, &ret->level);
                }
                return r;
        } else if (!S_ISLNK(st.st_mode)) {
                return -ENOTSUP;
        }

        r = readlink_malloc(path, &p);
        if (r < 0)
                return r;

        r = -ENOTSUP;
        if (startswith(p, "/sys/firmware/efi/efivars")) {
                r = store_efivars_get_auth(uuid, ret);
        }

        if (r == -ENOTSUP) {
                ret->level = AUTH_MISSING;
                ret->store = STORE_NONE;
        }

        return r;
}

#define ID128_UUID_FMT "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"

#define TB_EFIVAR_PATH_PREFIX "/sys/firmware/efi/efivars/Thunderbolt-"
#define TB_EFIVAR_PATH TB_EFIVAR_PATH_PREFIX ID128_UUID_FMT

static int store_efivars_put_auth(TbStore *store,
                                  const char *uuid,
                                  Auth *auth) {
        _cleanup_free_ char *target = NULL;
        char buf[FORMAT_SECURITY_MAX];
        sd_id128_t id;
        char *path;
        int r;


        if (sd_id128_from_string (uuid, &id) < 0) {
                return -EINVAL;
        }

        if (auth->level == AUTH_KEY) {
                r = efi_set_variable(id, "Thunderbolt", auth->key, KEY_CHARS);
        } else {
                xsprintf(buf, "%hhu", (uint8_t) auth->level);
                r = efi_set_variable(id, "Thunderbolt", buf, 1);
        }

        if (r < 0)
                return r;

        if (asprintf(&target, TB_EFIVAR_PATH, SD_ID128_FORMAT_VAL(id)) < 0)
                 return -ENOMEM;

        path = strjoina(store->path, "/authorization/", uuid);

        r = mkdir_parents(path, 0755);
        if (r < 0)
                return r;

        return symlink_idempotent(target, path);
}


static int store_fsdb_put_auth(TbStore *store,
                               const char *uuid,
                               Auth *auth) {
        char buf[KEY_CHARS + 1];
        char *path;
        int r;

        if (auth->level == AUTH_KEY) {
                xsprintf(buf, "%s", auth->key);
        } else {
                xsprintf(buf, "%hhu", (uint8_t) auth->level);
        }

        path = strjoina(store->path, "/authorization/", uuid);
        r = mkdir_parents(path, 0755);
        if (r < 0)
                return r;

        return write_string_file(path, buf, WRITE_STRING_FILE_CREATE);
}


int store_put_device(TbStore *store, TbDevice *device, Auth *auth) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *uuid;
        char *path;
        int r;

        uuid = device->uuid;

        switch (store->store) {
        case STORE_FSDB:
                r = store_fsdb_put_auth(store, uuid, auth);
                break;

        case STORE_EFIVARS:
                r = store_efivars_put_auth(store, uuid, auth);
                break;

        default:
                r = -ENOTSUP;
        }

        if (r < 0)
                return r;

        path = strjoina(store->path, "/devices/", uuid);
        r = mkdir_parents(path, 0755);
        if (r < 0)
                return r;

        f = fopen(path, "we");
        if (f == NULL)
                return -errno;

        fputs("[device]\n", f);
        fputs(" name=", f);
        fputs(device->name, f);
        fputs("\n vendor=", f);
        fputs(device->vendor, f);
        fputs("\n", f);

        return fflush_and_check(f);
}

bool tb_store_have_device(TbStore *store, const char *uuid) {
        char *p;
        struct stat st;

        if (in_initrd()) {
                p = strjoina(TB_EFIVAR_PATH_PREFIX, uuid);
        } else {
                p = strjoina(store->path, "/devices/", uuid);
        }

        return stat(p, &st) == 0;
}

int tb_store_list_ids(TbStore *store, char ***ret) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        char *p;

        assert(store);
        assert(ret);
        *ret = NULL;

        p = strjoina(store->path, "/devices/");
        d = opendir(p);
        if (!d)
                return errno == ENOENT ? true : -errno;

        FOREACH_DIRENT(de, d, return -errno) {
                strv_extend(ret, de->d_name);
        }

        return 0;
}

int tb_store_load_missing(TbStore *store, TbDeviceVec **devices) {
        TbDeviceVec *v;
        TbDevice *device;
        char **ids = NULL;
        char **i;
        int r;

        v = tb_device_vec_ensure_allocated(devices);
        if (v == NULL)
                return -ENOMEM;

        r = tb_store_list_ids(store, &ids);
        if (r < 0)
                return r;

        STRV_FOREACH(i, ids) {
                const char *id = *i;
                if (tb_device_vec_contains_uuid(v, id))
                        continue;

                r = tb_store_device_load(store, id, &device);
                if (r < 0) {
                        log_warning_errno(r, "Could not load device %s from DB: %m", id);
                        continue;
                }

                tb_device_vec_push_back(v, device);
        }

        return 0;
}

int tb_store_remove_auth(TbStore *store, const char *uuid) {
        _cleanup_free_ char *p = NULL;
        struct stat st;
        char *path;
        int r;

        if (in_initrd())
                return -EPERM;

        path = strjoina(store->path, "/authorization/", uuid);

        r = lstat(path, &st);
        if (r < 0)
                return -errno;

        if (S_ISREG(st.st_mode)) {
                r = unlink(path);
                return r < 0 ? -errno : 0;
        }

        r = readlink_malloc(path, &p);
        if (r < 0)
                return r;

        if (startswith(p, "/sys/firmware/efi/efivars")) {
                r = chattr_path(p, 0, FS_IMMUTABLE_FL);
                if (r < 0)
                        return r;
        }

        r = unlink(p);
        if (r < 0) {
                return -errno;
        }

        r = unlink(path);
        return r < 0 ? -errno : 0;
}

int tb_store_remove_device(TbStore *store, const char *uuid) {
        char *p;
        int r;

        if (in_initrd())
                return -EPERM;

        p = strjoina(store->path, "/devices/", uuid);
        r = unlink(p);
        if (r < 0)
                return -errno;

        return 0;
}
