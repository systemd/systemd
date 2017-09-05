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

/* the strings here correspond to the values reported
 * in sysfs ('security' attribute) for the domain  */
static const char* const security_table[_SECURITY_MAX] = {
        [SECURITY_NONE]    = "none",
        [SECURITY_USER]    = "user",
        [SECURITY_SECURE]  = "secure",
        [SECURITY_DPONLY]  = "dponly",
};
DEFINE_STRING_TABLE_LOOKUP(security, SecurityLevel);



void auth_reset(Auth *a) {
        a->key = string_free_erase(a->key);
        a->level = AUTH_MISSING;
        a->store = 0;
}

void auth_generate_key_string(Auth *a) {
        uint8_t rnddata[KEY_BYTES];
        char *keydata;
        int i;

        random_bytes(rnddata, KEY_BYTES);

        keydata = malloc(KEY_CHARS + 1);
        for (i = 0; i < KEY_BYTES; i++)
                snprintf(keydata + i*2, HEX_BYTES, "%02hhx", rnddata[i]);

        a->key = keydata;
        a->store = STORE_NONE;
}


void tb_device_free(TbDevice **device) {
        TbDevice *d;

        if (!*device)
                return;

        d = *device;

        free(d->uuid);
        free(d->name);
        free(d->vendor);

        if (d->udev)
                udev_device_unref(d->udev);
        if (d->devdir)
                (void) closedir(d->devdir);

        free(d);
        *device = NULL;
}

// -1, a < b; 0, a == b; 1, a > b
int tb_device_compare(const void *ia, const void *ib) {
        const TbDevice *a = ia;
        const TbDevice *b = ib;
        const char *pa, *pb;
        size_t la, lb;

        assert(a);
        assert(b);

        if (!a->udev && !b->udev)
                return strcmp_ptr(a->name, b->name);
        else if (!b->udev)
                return -1;
        else if (!a->udev)
                return 1;

        /* both have udev devices */
        assert(a->udev);
        assert(b->udev);

        pa = udev_device_get_syspath(a->udev);
        pb = udev_device_get_syspath(b->udev);

        la = strlen_ptr(pa);
        lb = strlen_ptr(pb);

        if (la != lb)
                return la - lb;

        /* sysfs path is same length, i.e. siblings */
        return strcmp_ptr(pa, pb);
}

static int tb_device_ptr_compare(const void *pa, const void *pb) {
        const TbDevice **a = (const TbDevice **) pa;
        const TbDevice **b = (const TbDevice **) pb;

        return tb_device_compare(*a, *b);
}

static void tb_device_hash_func(const void *p, struct siphash *state) {
        const TbDevice *d = p;
        siphash24_compress(d->uuid, strlen(d->uuid) + 1, state);
}

const struct hash_ops tb_device_hash_ops = {
        .hash = tb_device_hash_func,
        .compare = tb_device_compare,

};

SecurityLevel tb_device_get_security_level(TbDevice *device) {
        struct udev_device *parent;
        const char *security;
        bool found;

        found = false;
        parent = device->udev;
        do {
                const char *name;
                parent = udev_device_get_parent(parent);
                if (!parent)
                        break;

                name = udev_device_get_sysname(parent);
                found = startswith(name, "domain");

        } while (!found);

        if (!found)
                return _SECURITY_INVALID;

        security = udev_device_get_sysattr_value(parent, "security");
        if (!security)
                return _SECURITY_INVALID;

        return security_from_string(security);
}

static int read_single_line_at(int dirfd, const char *name, char **l_out) {
   _cleanup_fclose_ FILE *fp = NULL;
        char line[LINE_MAX], *l;
        int fd;

        fd = openat(dirfd, name, O_NOFOLLOW|O_CLOEXEC|O_RDONLY);
        if (fd < 0)
                return -errno;

        fp = fdopen(fd, "re");
        if (!fp)
                return -errno;

        l = fgets(line, sizeof(line), fp);
        if (!l) {
                if (ferror(fp))
                        return errno > 0 ? -errno : -EIO;

                line[0] = '\0';
        }

        l = strdup(truncate_nl(line));
        if (!l)
                return -ENOMEM;

        *l_out = l;
        return 0;
}

static char *get_sysattr_name(struct udev_device *udev, const char *attr) {
        char *s;
        const char *v;

        s = strjoina(attr, "_name");
        v = udev_device_get_sysattr_value(udev, s);
        if (v == NULL)
                v = udev_device_get_sysattr_value(udev, attr);
        if (v == NULL)
                return NULL;

        return strdup(v);
}

int tb_device_new_from_udev(struct udev_device *udev, TbDevice **ret) {
        _cleanup_tb_device_free_ TbDevice *d = NULL;
        _cleanup_free_ char *val = NULL;
        const char *syspath;
        int r;

        d = new0(TbDevice, 1);
        if (!d)
                return -ENOMEM;

        syspath = udev_device_get_syspath(udev);
        d->devdir = opendir(syspath);
        if (!d->devdir)
                return -errno;

        r = read_single_line_at(dirfd(d->devdir), "unique_id", &d->uuid);
        if (r < 0)
                return r;

        r = read_single_line_at(dirfd(d->devdir), "authorized", &val);
        if (r < 0)
                return r;

        r = safe_atoi(val, &d->authorized);
        if (r < 0)
                return r;

        d->udev = udev_device_ref(udev);
        d->name = get_sysattr_name(udev, "device");
        d->vendor = get_sysattr_name(udev, "vendor");

        if (!d->name || !d->vendor)
                return -ENOMEM;

        *ret = d;
        d = NULL;

        return 0;
}

int tb_device_new_from_syspath(struct udev *udev, const char *path, TbDevice **d) {
        _cleanup_udev_device_unref_ struct udev_device *udevice = NULL;

        udevice = udev_device_new_from_syspath(udev, path);
        if (udevice == NULL)
                return -ENODEV;

        return tb_device_new_from_udev(udevice, d);
}

int tb_device_authorize(TbDevice *dev, Auth *auth) {
        char buf[FORMAT_SECURITY_MAX];
        _cleanup_close_ int fd = -1;
        AuthLevel l;
        ssize_t n;
        int dfd;

        assert(dev);
        assert(auth);
        assert(auth->level > 0);

        if (dev->devdir == NULL)
                return -EINVAL;

        dfd = dirfd(dev->devdir);
        l = auth->level;

        if (l == AUTH_KEY) {
                _cleanup_close_ int key_fd = -1;

                if (auth->key == NULL)
                        return -EINVAL;

                key_fd = openat(dfd, "key", O_WRONLY|O_CLOEXEC);
                if (key_fd < 0)
                        return -errno;

                n = write(key_fd, auth->key, KEY_CHARS);

                if (n < 0)
                        return -errno;
                else if (n != KEY_CHARS)
                        return -EIO;

                /* if the key is not stored, we need to use
                 * AUTH_USER to write the new key to the device */
                if (auth->store == STORE_NONE)
                        l = AUTH_USER;

        }

        fd = openat(dfd, "authorized", O_WRONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        xsprintf(buf, "%hhu", (uint8_t) l);
        n = write(fd, buf, 1);

        if (n < 0)
                return -errno;
        else if (n != 1)
                return -EIO;

        return 0;
}

bool tb_device_is_online(TbDevice *dev) {
        assert(dev);

        return dev->udev != NULL;
}


void tb_device_vec_free(TbDeviceVec **vec) {
        TbDeviceVec *v;

        if (!vec || !*vec)
                return;

        v = *vec;

        free(v->devices);
        free(v);

        *vec = NULL;
}

TbDeviceVec *tb_device_vec_ensure_allocated(TbDeviceVec **vec) {
        TbDeviceVec *v;

        assert(vec);
        if (*vec != NULL)
                return *vec;

        v = *vec = new(TbDeviceVec, 1);

        v->n = 0;
        v->a = 2;
        v->devices = new0(TbDevice *, v->a);

        return v;
};

bool tb_device_vec_contains_uuid(TbDeviceVec *v, const char *uuid) {
        unsigned i;

        assert(v);
        assert(uuid);

        for (i = 0; i < v->n; i++) {
                TbDevice *d = tb_device_vec_at(v, i);
                if (streq(d->uuid, uuid))
                        return true;
        }

        return false;
}

void tb_device_vec_push_back(TbDeviceVec *v, TbDevice *d) {
        unsigned n = v->n + 1;
        assert(n != 0);

        if (n == v->a) {
                unsigned a = v->a * 2;
                assert(a > v->a);
                v->devices = realloc_multiply(v->devices, sizeof(TbDevice *), a);
                v->a = a;
        }
        v->devices[v->n] = d;
        v->n = n;
}

void tb_device_vec_sort(TbDeviceVec *v) {
        if (v == NULL)
                return;

        qsort(v->devices, v->n,
              sizeof(TbDevice *),
              tb_device_ptr_compare);
}
