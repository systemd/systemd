/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "dirent-util.h"
#include "efivars.h"
#include "fd-util.h"
#include "io-util.h"
#include "macro.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"
#include "util.h"
#include "virt.h"

#if ENABLE_EFI

#define LOAD_OPTION_ACTIVE            0x00000001
#define MEDIA_DEVICE_PATH                   0x04
#define MEDIA_HARDDRIVE_DP                  0x01
#define MEDIA_FILEPATH_DP                   0x04
#define SIGNATURE_TYPE_GUID                 0x02
#define MBR_TYPE_EFI_PARTITION_TABLE_HEADER 0x02
#define END_DEVICE_PATH_TYPE                0x7f
#define END_ENTIRE_DEVICE_PATH_SUBTYPE      0xff
#define EFI_OS_INDICATIONS_BOOT_TO_FW_UI    0x0000000000000001

struct boot_option {
        uint32_t attr;
        uint16_t path_len;
        uint16_t title[];
} _packed_;

struct drive_path {
        uint32_t part_nr;
        uint64_t part_start;
        uint64_t part_size;
        char signature[16];
        uint8_t mbr_type;
        uint8_t signature_type;
} _packed_;

struct device_path {
        uint8_t type;
        uint8_t sub_type;
        uint16_t length;
        union {
                uint16_t path[0];
                struct drive_path drive;
        };
} _packed_;

bool is_efi_boot(void) {
        if (detect_container() > 0)
                return false;

        return access("/sys/firmware/efi/", F_OK) >= 0;
}

static int read_flag(const char *varname) {
        _cleanup_free_ void *v = NULL;
        uint8_t b;
        size_t s;
        int r;

        if (!is_efi_boot()) /* If this is not an EFI boot, assume the queried flags are zero */
                return 0;

        r = efi_get_variable(EFI_VENDOR_GLOBAL, varname, NULL, &v, &s);
        if (r < 0)
                return r;

        if (s != 1)
                return -EINVAL;

        b = *(uint8_t *)v;
        return !!b;
}

bool is_efi_secure_boot(void) {
        return read_flag("SecureBoot") > 0;
}

bool is_efi_secure_boot_setup_mode(void) {
        return read_flag("SetupMode") > 0;
}

int efi_reboot_to_firmware_supported(void) {
        _cleanup_free_ void *v = NULL;
        uint64_t b;
        size_t s;
        int r;

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = efi_get_variable(EFI_VENDOR_GLOBAL, "OsIndicationsSupported", NULL, &v, &s);
        if (r == -ENOENT) /* variable doesn't exist? it's not supported then */
                return -EOPNOTSUPP;
        if (r < 0)
                return r;
        if (s != sizeof(uint64_t))
                return -EINVAL;

        b = *(uint64_t*) v;
        if (!(b & EFI_OS_INDICATIONS_BOOT_TO_FW_UI))
                return -EOPNOTSUPP; /* bit unset? it's not supported then */

        return 0;
}

static int get_os_indications(uint64_t *os_indication) {
        _cleanup_free_ void *v = NULL;
        size_t s;
        int r;

        /* Let's verify general support first */
        r = efi_reboot_to_firmware_supported();
        if (r < 0)
                return r;

        r = efi_get_variable(EFI_VENDOR_GLOBAL, "OsIndications", NULL, &v, &s);
        if (r == -ENOENT) {
                /* Some firmware implementations that do support OsIndications and report that with
                 * OsIndicationsSupported will remove the OsIndications variable when it is unset. Let's pretend it's 0
                 * then, to hide this implementation detail. Note that this call will return -ENOENT then only if the
                 * support for OsIndications is missing entirely, as determined by efi_reboot_to_firmware_supported()
                 * above. */
                *os_indication = 0;
                return 0;
        } else if (r < 0)
                return r;
        else if (s != sizeof(uint64_t))
                return -EINVAL;

        *os_indication = *(uint64_t *)v;
        return 0;
}

int efi_get_reboot_to_firmware(void) {
        int r;
        uint64_t b;

        r = get_os_indications(&b);
        if (r < 0)
                return r;

        return !!(b & EFI_OS_INDICATIONS_BOOT_TO_FW_UI);
}

int efi_set_reboot_to_firmware(bool value) {
        int r;
        uint64_t b, b_new;

        r = get_os_indications(&b);
        if (r < 0)
                return r;

        if (value)
                b_new = b | EFI_OS_INDICATIONS_BOOT_TO_FW_UI;
        else
                b_new = b & ~EFI_OS_INDICATIONS_BOOT_TO_FW_UI;

        /* Avoid writing to efi vars store if we can due to firmware bugs. */
        if (b != b_new)
                return efi_set_variable(EFI_VENDOR_GLOBAL, "OsIndications", &b_new, sizeof(uint64_t));

        return 0;
}

int efi_get_variable(
                sd_id128_t vendor,
                const char *name,
                uint32_t *attribute,
                void **value,
                size_t *size) {

        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *p = NULL;
        uint32_t a;
        ssize_t n;
        struct stat st;
        _cleanup_free_ void *buf = NULL;

        assert(name);
        assert(value);
        assert(size);

        if (asprintf(&p,
                     "/sys/firmware/efi/efivars/%s-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     name, SD_ID128_FORMAT_VAL(vendor)) < 0)
                return -ENOMEM;

        fd = open(p, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;
        if (st.st_size < 4)
                return -EIO;
        if (st.st_size > 4*1024*1024 + 4)
                return -E2BIG;

        n = read(fd, &a, sizeof(a));
        if (n < 0)
                return -errno;
        if (n != sizeof(a))
                return -EIO;

        buf = malloc(st.st_size - 4 + 2);
        if (!buf)
                return -ENOMEM;

        n = read(fd, buf, (size_t) st.st_size - 4);
        if (n < 0)
                return -errno;
        if (n != (ssize_t) st.st_size - 4)
                return -EIO;

        /* Always NUL terminate (2 bytes, to protect UTF-16) */
        ((char*) buf)[st.st_size - 4] = 0;
        ((char*) buf)[st.st_size - 4 + 1] = 0;

        *value = TAKE_PTR(buf);
        *size = (size_t) st.st_size - 4;

        if (attribute)
                *attribute = a;

        return 0;
}

int efi_set_variable(
                sd_id128_t vendor,
                const char *name,
                const void *value,
                size_t size) {

        struct var {
                uint32_t attr;
                char buf[];
        } _packed_ * _cleanup_free_ buf = NULL;
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        bool saved_flags_valid = false;
        unsigned saved_flags;
        int r;

        assert(name);
        assert(value || size == 0);

        if (asprintf(&p,
                     "/sys/firmware/efi/efivars/%s-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     name, SD_ID128_FORMAT_VAL(vendor)) < 0)
                return -ENOMEM;

        /* Newer efivarfs protects variables that are not in a whitelist with FS_IMMUTABLE_FL by default, to protect
         * them for accidental removal and modification. We are not changing these variables accidentally however,
         * hence let's unset the bit first. */

        r = chattr_path(p, 0, FS_IMMUTABLE_FL, &saved_flags);
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to drop FS_IMMUTABLE_FL flag from '%s', ignoring: %m", p);

        saved_flags_valid = r >= 0;

        if (size == 0) {
                if (unlink(p) < 0) {
                        r = -errno;
                        goto finish;
                }

                return 0;
        }

        fd = open(p, O_WRONLY|O_CREAT|O_NOCTTY|O_CLOEXEC, 0644);
        if (fd < 0) {
                r = -errno;
                goto finish;
        }

        buf = malloc(sizeof(uint32_t) + size);
        if (!buf) {
                r = -ENOMEM;
                goto finish;
        }

        buf->attr = EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS;
        memcpy(buf->buf, value, size);

        r = loop_write(fd, buf, sizeof(uint32_t) + size, false);
        if (r < 0)
                goto finish;

        r = 0;

finish:
        if (saved_flags_valid) {
                int q;

                /* Restore the original flags field, just in case */
                if (fd < 0)
                        q = chattr_path(p, saved_flags, FS_IMMUTABLE_FL, NULL);
                else
                        q = chattr_fd(fd, saved_flags, FS_IMMUTABLE_FL, NULL);
                if (q < 0)
                        log_debug_errno(q, "Failed to restore FS_IMMUTABLE_FL on '%s', ignoring: %m", p);
        }

        return r;
}

int efi_get_variable_string(sd_id128_t vendor, const char *name, char **p) {
        _cleanup_free_ void *s = NULL;
        size_t ss = 0;
        int r;
        char *x;

        r = efi_get_variable(vendor, name, NULL, &s, &ss);
        if (r < 0)
                return r;

        x = utf16_to_utf8(s, ss);
        if (!x)
                return -ENOMEM;

        *p = x;
        return 0;
}

static size_t utf16_size(const uint16_t *s) {
        size_t l = 0;

        while (s[l] > 0)
                l++;

        return (l+1) * sizeof(uint16_t);
}

static void efi_guid_to_id128(const void *guid, sd_id128_t *id128) {
        struct uuid {
                uint32_t u1;
                uint16_t u2;
                uint16_t u3;
                uint8_t u4[8];
        } _packed_;
        const struct uuid *uuid = guid;

        id128->bytes[0] = (uuid->u1 >> 24) & 0xff;
        id128->bytes[1] = (uuid->u1 >> 16) & 0xff;
        id128->bytes[2] = (uuid->u1 >> 8) & 0xff;
        id128->bytes[3] = (uuid->u1) & 0xff;
        id128->bytes[4] = (uuid->u2 >> 8) & 0xff;
        id128->bytes[5] = (uuid->u2) & 0xff;
        id128->bytes[6] = (uuid->u3 >> 8) & 0xff;
        id128->bytes[7] = (uuid->u3) & 0xff;
        memcpy(&id128->bytes[8], uuid->u4, sizeof(uuid->u4));
}

int efi_get_boot_option(
                uint16_t id,
                char **title,
                sd_id128_t *part_uuid,
                char **path,
                bool *active) {

        char boot_id[9];
        _cleanup_free_ uint8_t *buf = NULL;
        size_t l;
        struct boot_option *header;
        size_t title_size;
        _cleanup_free_ char *s = NULL, *p = NULL;
        sd_id128_t p_uuid = SD_ID128_NULL;
        int r;

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        xsprintf(boot_id, "Boot%04X", id);
        r = efi_get_variable(EFI_VENDOR_GLOBAL, boot_id, NULL, (void **)&buf, &l);
        if (r < 0)
                return r;
        if (l < sizeof(struct boot_option))
                return -ENOENT;

        header = (struct boot_option *)buf;
        title_size = utf16_size(header->title);
        if (title_size > l - offsetof(struct boot_option, title))
                return -EINVAL;

        if (title) {
                s = utf16_to_utf8(header->title, title_size);
                if (!s)
                        return -ENOMEM;
        }

        if (header->path_len > 0) {
                uint8_t *dbuf;
                size_t dnext, doff;

                doff = offsetof(struct boot_option, title) + title_size;
                dbuf = buf + doff;
                if (header->path_len > l - doff)
                        return -EINVAL;

                dnext = 0;
                while (dnext < header->path_len) {
                        struct device_path *dpath;

                        dpath = (struct device_path *)(dbuf + dnext);
                        if (dpath->length < 4)
                                break;

                        /* Type 0x7F – End of Hardware Device Path, Sub-Type 0xFF – End Entire Device Path */
                        if (dpath->type == END_DEVICE_PATH_TYPE && dpath->sub_type == END_ENTIRE_DEVICE_PATH_SUBTYPE)
                                break;

                        dnext += dpath->length;

                        /* Type 0x04 – Media Device Path */
                        if (dpath->type != MEDIA_DEVICE_PATH)
                                continue;

                        /* Sub-Type 1 – Hard Drive */
                        if (dpath->sub_type == MEDIA_HARDDRIVE_DP) {
                                /* 0x02 – GUID Partition Table */
                                if (dpath->drive.mbr_type != MBR_TYPE_EFI_PARTITION_TABLE_HEADER)
                                        continue;

                                /* 0x02 – GUID signature */
                                if (dpath->drive.signature_type != SIGNATURE_TYPE_GUID)
                                        continue;

                                if (part_uuid)
                                        efi_guid_to_id128(dpath->drive.signature, &p_uuid);
                                continue;
                        }

                        /* Sub-Type 4 – File Path */
                        if (dpath->sub_type == MEDIA_FILEPATH_DP && !p && path) {
                                p = utf16_to_utf8(dpath->path, dpath->length-4);
                                if (!p)
                                        return  -ENOMEM;

                                efi_tilt_backslashes(p);
                                continue;
                        }
                }
        }

        if (title)
                *title = TAKE_PTR(s);
        if (part_uuid)
                *part_uuid = p_uuid;
        if (path)
                *path = TAKE_PTR(p);
        if (active)
                *active = !!(header->attr & LOAD_OPTION_ACTIVE);

        return 0;
}

static void to_utf16(uint16_t *dest, const char *src) {
        int i;

        for (i = 0; src[i] != '\0'; i++)
                dest[i] = src[i];
        dest[i] = '\0';
}

struct guid {
        uint32_t u1;
        uint16_t u2;
        uint16_t u3;
        uint8_t u4[8];
} _packed_;

static void id128_to_efi_guid(sd_id128_t id, void *guid) {
        struct guid *uuid = guid;

        uuid->u1 = id.bytes[0] << 24 | id.bytes[1] << 16 | id.bytes[2] << 8 | id.bytes[3];
        uuid->u2 = id.bytes[4] << 8 | id.bytes[5];
        uuid->u3 = id.bytes[6] << 8 | id.bytes[7];
        memcpy(uuid->u4, id.bytes+8, sizeof(uuid->u4));
}

static uint16_t *tilt_slashes(uint16_t *s) {
        uint16_t *p;

        for (p = s; *p; p++)
                if (*p == '/')
                        *p = '\\';

        return s;
}

int efi_add_boot_option(
                uint16_t id,
                const char *title,
                uint32_t part,
                uint64_t pstart,
                uint64_t psize,
                sd_id128_t part_uuid,
                const char *path) {

        size_t size, title_len, path_len;
        _cleanup_free_ char *buf = NULL;
        struct boot_option *option;
        struct device_path *devicep;
        char boot_id[9];

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        title_len = (strlen(title)+1) * 2;
        path_len = (strlen(path)+1) * 2;

        buf = malloc0(sizeof(struct boot_option) + title_len +
                      sizeof(struct drive_path) +
                      sizeof(struct device_path) + path_len);
        if (!buf)
                return -ENOMEM;

        /* header */
        option = (struct boot_option *)buf;
        option->attr = LOAD_OPTION_ACTIVE;
        option->path_len = offsetof(struct device_path, drive) + sizeof(struct drive_path) +
                           offsetof(struct device_path, path) + path_len +
                           offsetof(struct device_path, path);
        to_utf16(option->title, title);
        size = offsetof(struct boot_option, title) + title_len;

        /* partition info */
        devicep = (struct device_path *)(buf + size);
        devicep->type = MEDIA_DEVICE_PATH;
        devicep->sub_type = MEDIA_HARDDRIVE_DP;
        devicep->length = offsetof(struct device_path, drive) + sizeof(struct drive_path);
        devicep->drive.part_nr = part;
        devicep->drive.part_start = pstart;
        devicep->drive.part_size = psize;
        devicep->drive.signature_type = SIGNATURE_TYPE_GUID;
        devicep->drive.mbr_type = MBR_TYPE_EFI_PARTITION_TABLE_HEADER;
        id128_to_efi_guid(part_uuid, devicep->drive.signature);
        size += devicep->length;

        /* path to loader */
        devicep = (struct device_path *)(buf + size);
        devicep->type = MEDIA_DEVICE_PATH;
        devicep->sub_type = MEDIA_FILEPATH_DP;
        devicep->length = offsetof(struct device_path, path) + path_len;
        to_utf16(devicep->path, path);
        tilt_slashes(devicep->path);
        size += devicep->length;

        /* end of path */
        devicep = (struct device_path *)(buf + size);
        devicep->type = END_DEVICE_PATH_TYPE;
        devicep->sub_type = END_ENTIRE_DEVICE_PATH_SUBTYPE;
        devicep->length = offsetof(struct device_path, path);
        size += devicep->length;

        xsprintf(boot_id, "Boot%04X", id);
        return efi_set_variable(EFI_VENDOR_GLOBAL, boot_id, buf, size);
}

int efi_remove_boot_option(uint16_t id) {
        char boot_id[9];

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        xsprintf(boot_id, "Boot%04X", id);
        return efi_set_variable(EFI_VENDOR_GLOBAL, boot_id, NULL, 0);
}

int efi_get_boot_order(uint16_t **order) {
        _cleanup_free_ void *buf = NULL;
        size_t l;
        int r;

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = efi_get_variable(EFI_VENDOR_GLOBAL, "BootOrder", NULL, &buf, &l);
        if (r < 0)
                return r;

        if (l <= 0)
                return -ENOENT;

        if (l % sizeof(uint16_t) > 0 ||
            l / sizeof(uint16_t) > INT_MAX)
                return -EINVAL;

        *order = TAKE_PTR(buf);
        return (int) (l / sizeof(uint16_t));
}

int efi_set_boot_order(uint16_t *order, size_t n) {

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        return efi_set_variable(EFI_VENDOR_GLOBAL, "BootOrder", order, n * sizeof(uint16_t));
}

static int boot_id_hex(const char s[4]) {
        int id = 0, i;

        for (i = 0; i < 4; i++)
                if (s[i] >= '0' && s[i] <= '9')
                        id |= (s[i] - '0') << (3 - i) * 4;
                else if (s[i] >= 'A' && s[i] <= 'F')
                        id |= (s[i] - 'A' + 10) << (3 - i) * 4;
                else
                        return -EINVAL;

        return id;
}

static int cmp_uint16(const uint16_t *a, const uint16_t *b) {
        return CMP(*a, *b);
}

int efi_get_boot_options(uint16_t **options) {
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ uint16_t *list = NULL;
        struct dirent *de;
        size_t alloc = 0;
        int count = 0;

        assert(options);

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        dir = opendir("/sys/firmware/efi/efivars/");
        if (!dir)
                return -errno;

        FOREACH_DIRENT(de, dir, return -errno) {
                int id;

                if (strncmp(de->d_name, "Boot", 4) != 0)
                        continue;

                if (strlen(de->d_name) != 45)
                        continue;

                if (strcmp(de->d_name + 8, "-8be4df61-93ca-11d2-aa0d-00e098032b8c") != 0)
                        continue;

                id = boot_id_hex(de->d_name + 4);
                if (id < 0)
                        continue;

                if (!GREEDY_REALLOC(list, alloc, count + 1))
                        return -ENOMEM;

                list[count++] = id;
        }

        typesafe_qsort(list, count, cmp_uint16);

        *options = TAKE_PTR(list);

        return count;
}

static int read_usec(sd_id128_t vendor, const char *name, usec_t *u) {
        _cleanup_free_ char *j = NULL;
        int r;
        uint64_t x = 0;

        assert(name);
        assert(u);

        r = efi_get_variable_string(EFI_VENDOR_LOADER, name, &j);
        if (r < 0)
                return r;

        r = safe_atou64(j, &x);
        if (r < 0)
                return r;

        *u = x;
        return 0;
}

int efi_loader_get_boot_usec(usec_t *firmware, usec_t *loader) {
        uint64_t x, y;
        int r;

        assert(firmware);
        assert(loader);

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = read_usec(EFI_VENDOR_LOADER, "LoaderTimeInitUSec", &x);
        if (r < 0)
                return r;

        r = read_usec(EFI_VENDOR_LOADER, "LoaderTimeExecUSec", &y);
        if (r < 0)
                return r;

        if (y == 0 || y < x)
                return -EIO;

        if (y > USEC_PER_HOUR)
                return -EIO;

        *firmware = x;
        *loader = y;

        return 0;
}

int efi_loader_get_device_part_uuid(sd_id128_t *u) {
        _cleanup_free_ char *p = NULL;
        int r, parsed[16];

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderDevicePartUUID", &p);
        if (r < 0)
                return r;

        if (sscanf(p, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   &parsed[0], &parsed[1], &parsed[2], &parsed[3],
                   &parsed[4], &parsed[5], &parsed[6], &parsed[7],
                   &parsed[8], &parsed[9], &parsed[10], &parsed[11],
                   &parsed[12], &parsed[13], &parsed[14], &parsed[15]) != 16)
                return -EIO;

        if (u) {
                unsigned i;

                for (i = 0; i < ELEMENTSOF(parsed); i++)
                        u->bytes[i] = parsed[i];
        }

        return 0;
}

int efi_loader_get_entries(char ***ret) {
        _cleanup_free_ char16_t *entries = NULL;
        _cleanup_strv_free_ char **l = NULL;
        size_t size, i, start;
        int r;

        assert(ret);

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = efi_get_variable(EFI_VENDOR_LOADER, "LoaderEntries", NULL, (void**) &entries, &size);
        if (r < 0)
                return r;

        /* The variable contains a series of individually NUL terminated UTF-16 strings. */

        for (i = 0, start = 0;; i++) {
                char *decoded;
                bool end;

                /* Is this the end of the variable's data? */
                end = i * sizeof(char16_t) >= size;

                /* Are we in the middle of a string? (i.e. not at the end of the variable, nor at a NUL terminator?) If
                 * so, let's go to the next entry. */
                if (!end && entries[i] != 0)
                        continue;

                /* We reached the end of a string, let's decode it into UTF-8 */
                decoded = utf16_to_utf8(entries + start, (i - start) * sizeof(char16_t));
                if (!decoded)
                        return -ENOMEM;

                r = strv_consume(&l, decoded);
                if (r < 0)
                        return r;

                /* We reached the end of the variable */
                if (end)
                        break;

                /* Continue after the NUL byte */
                start = i + 1;
        }

        *ret = TAKE_PTR(l);
        return 0;
}

#endif

char *efi_tilt_backslashes(char *s) {
        char *p;

        for (p = s; *p; p++)
                if (*p == '\\')
                        *p = '/';

        return s;
}
