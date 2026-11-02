/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

#include "alloc-util.h"
#include "dm-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "parse-util.h"
#include "string-util.h"

int dm_deferred_remove_cancel(const char *name) {
        _cleanup_close_ int fd = -EBADF;

        struct combined {
                struct dm_ioctl dm_ioctl;
                struct dm_target_msg dm_target_msg;
        } _packed_;

        union message {
                struct combined combined;
                struct {
                        uint8_t space[offsetof(struct combined, dm_target_msg.message)];
                        char text[STRLEN("@cancel_deferred_remove") + 1];
                } _packed_;
        } message = {
                .combined.dm_ioctl = {
                        .version = {
                                DM_VERSION_MAJOR,
                                DM_VERSION_MINOR,
                                DM_VERSION_PATCHLEVEL
                        },
                        .data_size = sizeof(union message),
                        .data_start = offsetof(union message, combined.dm_target_msg),
                },
        };

        assert(name);

        if (strlen(name) >= sizeof(message.combined.dm_ioctl.name))
                return -ENODEV; /* A device with a name longer than this cannot possibly exist */

        strncpy_exact(message.combined.dm_ioctl.name, name, sizeof(message.combined.dm_ioctl.name));
        strncpy_exact(message.text, "@cancel_deferred_remove", sizeof(message.text));

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, DM_TARGET_MSG, &message))
                return -errno;

        return 0;
}

int dm_table_status(dev_t devnum, char **ret_target_type, char **ret_params) {
        _cleanup_free_ struct dm_ioctl *dmi = NULL;
        _cleanup_close_ int fd = -EBADF;
        size_t size = 16U * 1024U;

        assert(ret_target_type);
        assert(ret_params);

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        for (;;) {
                free(dmi);
                dmi = malloc0(size);
                if (!dmi)
                        return -ENOMEM;

                /* The kernel decodes .dev with huge_decode_dev(). We encode the device number the same way,
                 * instead of relying on how the C library encodes dev_t. */
                *dmi = (struct dm_ioctl) {
                        .version = {
                                DM_VERSION_MAJOR,
                                DM_VERSION_MINOR,
                                DM_VERSION_PATCHLEVEL
                        },
                        .data_size = size,
                        .data_start = sizeof(struct dm_ioctl),
                        .flags = DM_STATUS_TABLE_FLAG,
                        .dev = (minor(devnum) & 0xffU) | (major(devnum) << 8) | ((uint64_t) (minor(devnum) & ~0xffU) << 12),
                };

                if (ioctl(fd, DM_TABLE_STATUS, dmi) < 0)
                        return -errno;

                if (!FLAGS_SET(dmi->flags, DM_BUFFER_FULL_FLAG))
                        break;

                if (size >= 1024U * 1024U)
                        return -E2BIG;

                size *= 2;
        }

        if (dmi->target_count == 0)
                return -ENXIO;
        if (dmi->target_count > 1)
                return -ENOTUNIQ;

        if (dmi->data_start < sizeof(struct dm_ioctl) ||
            dmi->data_size > size ||
            dmi->data_size < dmi->data_start ||
            dmi->data_size - dmi->data_start < sizeof(struct dm_target_spec) + 1)
                return -EBADMSG;

        const struct dm_target_spec *spec = (const struct dm_target_spec*) ((const uint8_t*) dmi + dmi->data_start);
        const char *params = (const char*) (spec + 1);
        size_t params_max = dmi->data_size - dmi->data_start - sizeof(struct dm_target_spec);

        if (!memchr(params, 0, params_max) || !memchr(spec->target_type, 0, sizeof(spec->target_type)))
                return -EBADMSG;

        _cleanup_free_ char *target_type = strdup(spec->target_type);
        if (!target_type)
                return -ENOMEM;

        char *p = strdup(params);
        if (!p)
                return -ENOMEM;

        *ret_target_type = TAKE_PTR(target_type);
        *ret_params = p;
        return 0;
}

int dm_verity_table_signed(const char *params, const char *root_hash) {
        unsigned n_opts;
        int r;

        assert(params);
        assert(root_hash);

        /* The table of a verity target has the following fields, followed by the optional arguments:
         * <version> <data device> <hash device> <data block size> <hash block size> <number of data blocks>
         * <hash start block> <algorithm> <root hash> <salt> */
        for (unsigned i = 0; i < 10; i++) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&params, &word, NULL, /* flags= */ 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBADMSG;

                if (i == 8 && !strcaseeq(word, root_hash))
                        return -ESTALE;
        }

        _cleanup_free_ char *word = NULL;
        r = extract_first_word(&params, &word, NULL, /* flags= */ 0);
        if (r < 0)
                return r;
        if (r == 0)
                return false;

        r = safe_atou(word, &n_opts);
        if (r < 0)
                return r;

        for (unsigned i = 0; i < n_opts; i++) {
                word = mfree(word);

                r = extract_first_word(&params, &word, NULL, /* flags= */ 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBADMSG;

                /* The kernel only loads a table with this argument if it validated the signature. */
                if (streq(word, "root_hash_sig_key_desc"))
                        return true;
        }

        return false;
}
