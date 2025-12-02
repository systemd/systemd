/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <fcntl.h>
#include <getopt.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "build.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "sd-device.h"
#include "string-util.h"
#include "time-util.h"
#include "udev-util.h"
#include "verbs.h"

static int get_size(const char *dev_path, uint64_t *ret_size) {
        _cleanup_close_ int fd = -EBADF;
        uint64_t block_size_bytes;

        assert(dev_path);
        assert(ret_size);

        fd = open(dev_path, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open device '%s': %m", dev_path);

        /* Use BLKGETSIZE64 ioctl to get block size in bytes */
        if (ioctl(fd, BLKGETSIZE64, &block_size_bytes) < 0)
                return log_error_errno(errno, "Failed to get device size for '%s': %m", dev_path);

        *ret_size = block_size_bytes / 512;
        return 0;
}

static int dm_ioctl_run(const char *name, uint32_t cmd, void *data, size_t data_size) {
        _cleanup_close_ int fd = -EBADF;
        struct dm_ioctl *dm = data;

        assert(name);
        assert(data);

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open /dev/mapper/control: %m");

        dm->version[0] = DM_VERSION_MAJOR;
        dm->version[1] = DM_VERSION_MINOR;
        dm->version[2] = DM_VERSION_PATCHLEVEL;
        dm->data_size = data_size;

        if (strlen(name) >= sizeof(dm->name))
                return log_error_errno(SYNTHETIC_ERRNO(ENAMETOOLONG), "Device name too long");
        strncpy_exact(dm->name, name, sizeof(dm->name));

        if (ioctl(fd, cmd, dm) < 0)
                return log_error_errno(errno, "DM ioctl failed: %m");

        return 0;
}

static int dm_create_device_ioctl(const char *name, uint64_t size_sectors, const char *target_params) {
        char *params_buf, devlink[PATH_MAX];
        size_t params_len, dm_size;
        struct dm_ioctl *dm;
        struct dm_target_spec *tgt;
        int r;

        assert(name);
        assert(target_params);

        /* Step 1: Create device */
        dm_size = sizeof(struct dm_ioctl);
        dm = alloca(dm_size);
        memzero(dm, dm_size);
        dm->dev = 0;

        r = dm_ioctl_run(name, DM_DEV_CREATE, dm, dm_size);
        if (r < 0)
                return r;

        /* Step 2: Load table with target */
        params_len = strlen(target_params) + 1;
        dm_size = sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec) + params_len;
        dm = alloca(dm_size);
        memzero(dm, dm_size);

        dm->data_start = sizeof(struct dm_ioctl);
        dm->target_count = 1;

        tgt = (struct dm_target_spec *) ((char *) dm + dm->data_start);
        tgt->sector_start = 0;
        tgt->length = size_sectors;
        strncpy(tgt->target_type, "clone", sizeof(tgt->target_type));
        tgt->next = 0;

        params_buf = (char *) tgt + sizeof(struct dm_target_spec);
        strcpy(params_buf, target_params);
        tgt->status = 0;

        r = dm_ioctl_run(name, DM_TABLE_LOAD, dm, dm_size);
        if (r < 0)
                return r;

        /* Step 3: Activate device (suspend with no flags = resume) */
        dm_size = sizeof(struct dm_ioctl);
        dm = alloca(dm_size);
        memzero(dm, dm_size);
        dm->flags = 0;

        r = dm_ioctl_run(name, DM_DEV_SUSPEND, dm, dm_size);
        if (r < 0)
                return r;

        /* Wait for udev to create /dev/mapper/<name> */
        xsprintf(devlink, "/dev/mapper/%s", name);
        r = device_wait_for_devlink(devlink, "block", 10 * USEC_PER_SEC, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for device %s: %m", devlink);

        return 0;
}

static int dm_send_message_ioctl(const char *name, const char *message) {
        struct dm_ioctl *dm;
        struct dm_target_msg *msg;
        size_t dm_size, msg_len;

        assert(name);
        assert(message);

        msg_len = strlen(message) + 1;
        dm_size = sizeof(struct dm_ioctl) + sizeof(struct dm_target_msg) + msg_len;
        dm = alloca(dm_size);
        memzero(dm, dm_size);

        dm->data_start = sizeof(struct dm_ioctl);

        msg = (struct dm_target_msg *) ((char *) dm + dm->data_start);
        msg->sector = 0;
        strcpy(msg->message, message);

        return dm_ioctl_run(name, DM_TARGET_MSG, dm, dm_size);
}

static int dm_clone_task(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev) {

        uint64_t device_size_sectors;
        char cmd[256];
        int r;

        assert(clone_name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        r = get_size(source_dev, &device_size_sectors);
        if (r < 0)
                return r;

        /* Build dm-clone target parameters:
         * Format: <metadata_dev> <dest_dev> <source_dev> <region_size> <version> <options>
         * region_size: 8 sectors (4KB regions)
         * version: 1
         * options: no_hydration (disable initial background hydration) */
        xsprintf(cmd, "%s %s %s 8 1 no_hydration", metadata_dev, dest_dev, source_dev);

        r = dm_create_device_ioctl(clone_name, device_size_sectors, cmd);
        if (r < 0)
                return r;

        return 0;
}

static int dm_msg_task(const char *clone_name) {
        int r;

        assert(clone_name);

        r = dm_send_message_ioctl(clone_name, "enable_hydration");
        if (r < 0)
                return r;

        return 0;
}

/* dm-clone device creation workflow:
 * 1. Create the dm-clone device
 * 2. Enable background hydration
 * 3. (Optional) Replace with linear mapping to finalize */
static int clone_device(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev) {

        char clone_dev_path[256];
        struct stat st;
        int r;

        assert(clone_name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        xsprintf(clone_dev_path, "/dev/mapper/%s", clone_name);
        if (stat(clone_dev_path, &st) >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Device '%s' already exists.", clone_dev_path);

        r = dm_clone_task(clone_name, source_dev, dest_dev, metadata_dev);
        if (r < 0)
                return log_error_errno(r, "Failed to create dm-clone device: %m");

        r = dm_msg_task(clone_name);
        if (r < 0)
                return log_error_errno(r, "Failed to send dm message: %m");

        return 0;
}

/* Arguments: systemd-dmclone add NAME SOURCE-DEVICE DST_DEVICE META-DEVICE [OPTIONS] */
static int verb_add(int argc, char *argv[], void *userdata) {
        int r;

        assert(argc >= 5 && argc <= 6);

        const char *name = ASSERT_PTR(argv[1]),
              *src_dev = ASSERT_PTR(argv[2]),
              *dst_dev = ASSERT_PTR(argv[3]),
              *meta_dev = ASSERT_PTR(argv[4]);

        log_debug("%s %s %s %s %s opts=%s ", __func__,
                  name, src_dev, dst_dev, meta_dev, "");

        r = clone_device(name, src_dev, dst_dev, meta_dev);
        if (r < 0)
                return r;

        return 0;
}

static int verb_remove(int argc, char *argv[], void *userdata) {

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-dmclone", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s add NAME SOURCE-DEVICE DST-DEVICE META-DEVICE [OPTIONS] \n"
                        "%1$s remove VOLUME\n\n"
                        "%2$sAdd or remove a dm clone device.%3$s\n\n"
                        "  -h --help            Show this help\n"
                        "     --version         Show package version\n"
                        "\nSee the %4$s for details.\n",
                        program_invocation_short_name,
                        ansi_highlight(),
                        ansi_normal(),
                        link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",                         no_argument,       NULL, 'h'                       },
                { "version",                      no_argument,       NULL, ARG_VERSION               },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        if (argv_looks_like_help(argc, argv))
                return help();

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                        case 'h':
                                return help();

                        case ARG_VERSION:
                                return version();

                        case '?':
                                return -EINVAL;

                        default:
                                assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();
        umask(0022);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        static const Verb verbs[] = {
                { "add", 5, 6, 0, verb_add },
                { "remove", 1, 1, 0, verb_remove },
                {}
        };
        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
