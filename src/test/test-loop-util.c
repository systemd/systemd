/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "capability-util.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "gpt.h"
#include "loop-util.h"
#include "mkfs-util.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "virt.h"

static unsigned arg_n_threads = 5;
static unsigned arg_n_iterations = 3;
static usec_t arg_timeout = 0;

#if HAVE_BLKID
static usec_t end = 0;

static void verify_dissected_image(DissectedImage *dissected) {
        ASSERT_TRUE(dissected->partitions[PARTITION_ESP].found);
        ASSERT_NOT_NULL(dissected->partitions[PARTITION_ESP].node);
        ASSERT_TRUE(dissected->partitions[PARTITION_XBOOTLDR].found);
        ASSERT_NOT_NULL(dissected->partitions[PARTITION_XBOOTLDR].node);
        ASSERT_TRUE(dissected->partitions[PARTITION_ROOT].found);
        ASSERT_NOT_NULL(dissected->partitions[PARTITION_ROOT].node);
        ASSERT_TRUE(dissected->partitions[PARTITION_HOME].found);
        ASSERT_NOT_NULL(dissected->partitions[PARTITION_HOME].node);
}

static void verify_dissected_image_harder(DissectedImage *dissected) {
        verify_dissected_image(dissected);

        ASSERT_STREQ(dissected->partitions[PARTITION_ESP].fstype, "vfat");
        ASSERT_STREQ(dissected->partitions[PARTITION_XBOOTLDR].fstype, "vfat");
        ASSERT_STREQ(dissected->partitions[PARTITION_ROOT].fstype, "ext4");
        ASSERT_STREQ(dissected->partitions[PARTITION_HOME].fstype, "ext4");
}

static void* thread_func(void *ptr) {
        int fd = PTR_TO_FD(ptr);

        for (unsigned i = 0; i < arg_n_iterations; i++) {
                _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
                _cleanup_(umount_and_rmdir_and_freep) char *mounted = NULL;
                _cleanup_(dissected_image_unrefp) DissectedImage *dissected = NULL;

                if (now(CLOCK_MONOTONIC) >= end) {
                        log_notice("Time's up, exiting thread's loop");
                        break;
                }

                log_notice("> Thread iteration #%u.", i);

                ASSERT_OK(mkdtemp_malloc(NULL, &mounted));

                ASSERT_OK(loop_device_make(fd, O_RDONLY, 0, UINT64_MAX, 0, LO_FLAGS_PARTSCAN, LOCK_SH, &loop));
                ASSERT_NOT_NULL(loop->dev);
                ASSERT_NOT_NULL(loop->backing_file);

                log_notice("Acquired loop device %s, will mount on %s", loop->node, mounted);

                ASSERT_OK(dissect_loop_device(
                                loop,
                                /* verity= */ NULL,
                                /* mount_options= */ NULL,
                                /* image_policy= */ NULL,
                                /* image_filter= */ NULL,
                                DISSECT_IMAGE_READ_ONLY|DISSECT_IMAGE_ADD_PARTITION_DEVICES|DISSECT_IMAGE_PIN_PARTITION_DEVICES,
                                &dissected));

                log_info("Dissected loop device %s", loop->node);

                for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                        if (!dissected->partitions[d].found)
                                continue;

                        log_notice("Found node %s fstype %s designator %s",
                                   dissected->partitions[d].node,
                                   dissected->partitions[d].fstype,
                                   partition_designator_to_string(d));
                }

                verify_dissected_image(dissected);

                ASSERT_OK(dissected_image_mount(
                                dissected,
                                mounted,
                                /* uid_shift= */ UID_INVALID,
                                /* uid_range= */ UID_INVALID,
                                /* userns_fd= */ -EBADF,
                                DISSECT_IMAGE_READ_ONLY));

                /* Now the block device is mounted, we don't need no manual lock anymore, the devices are now
                 * pinned by the mounts. */
                ASSERT_OK(loop_device_flock(loop, LOCK_UN));

                log_notice("Unmounting %s", mounted);
                mounted = umount_and_rmdir_and_free(mounted);

                log_notice("Unmounted.");

                dissected = dissected_image_unref(dissected);

                log_notice("Detaching loop device %s", loop->node);
                loop = loop_device_unref(loop);
                log_notice("Detached loop device.");
        }

        log_notice("Leaving thread");

        return NULL;
}
#endif

static bool have_root_gpt_type(void) {
#ifdef SD_GPT_ROOT_NATIVE
        return true;
#else
        return false;
#endif
}

static int intro(void) {
        int r;

        log_show_tid(true);
        log_show_time(true);
        log_show_color(true);

        if (saved_argc >= 2) {
                r = safe_atou(saved_argv[1], &arg_n_threads);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse first argument (number of threads): %s", saved_argv[1]);
                if (arg_n_threads <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Number of threads must be at least 1, refusing.");
        }

        if (saved_argc >= 3) {
                r = safe_atou(saved_argv[2], &arg_n_iterations);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse second argument (number of iterations): %s", saved_argv[2]);
                if (arg_n_iterations <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Number of iterations must be at least 1, refusing.");
        }

        if (saved_argc >= 4) {
                r = parse_sec(saved_argv[3], &arg_timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse third argument (timeout): %s", saved_argv[3]);
        }

        if (saved_argc >= 5)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments (expected 3 at max).");

        if (!have_root_gpt_type())
                return log_tests_skipped("No root partition GPT defined for this architecture");

        r = find_executable("sfdisk", NULL);
        if (r < 0)
                return log_tests_skipped_errno(r, "Could not find sfdisk command");

        return EXIT_SUCCESS;
}

TEST(loop_block) {
#if HAVE_BLKID
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted = NULL;
        pthread_t threads[arg_n_threads];
        sd_id128_t id;
#endif
        _cleanup_free_ char *p = NULL, *cmd = NULL;
        _cleanup_pclose_ FILE *sfdisk = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_close_ int fd = -EBADF;

        ASSERT_OK(tempfn_random_child("/var/tmp", "sfdisk", &p));
        fd = ASSERT_OK_ERRNO(open(p, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW, 0666));
        ASSERT_OK_ERRNO(ftruncate(fd, 256*1024*1024));

        cmd = ASSERT_NOT_NULL(strjoin("sfdisk ", p));
        sfdisk = ASSERT_NOT_NULL(popen(cmd, "we"));

        /* A reasonably complex partition table that fits on a 64K disk */
        fputs("label: gpt\n"
              "size=32M, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B\n"
              "size=32M, type=BC13C2FF-59E6-4262-A352-B275FD6F7172\n"
              "size=32M, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F\n"
              "size=32M, type=", sfdisk);

#ifdef SD_GPT_ROOT_NATIVE
        fprintf(sfdisk, SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(SD_GPT_ROOT_NATIVE));
#else
        fprintf(sfdisk, SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(SD_GPT_ROOT_X86_64));
#endif

        fputs("\n"
              "size=32M, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915\n", sfdisk);

        ASSERT_EQ(pclose(sfdisk), 0);
        sfdisk = NULL;

#if HAVE_BLKID
        ASSERT_OK(dissect_image_file(
                                  p,
                                  /* verity= */ NULL,
                                  /* mount_options= */ NULL,
                                  /* image_policy= */ NULL,
                                  /* image_filter= */ NULL,
                                  /* flags= */ 0,
                                  &dissected));
        verify_dissected_image(dissected);
        dissected = dissected_image_unref(dissected);
#endif

        if (have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                log_tests_skipped("not running privileged");
                return;
        }

        if (detect_container() != 0 || running_in_chroot() != 0) {
                log_tests_skipped("Test not supported in a container/chroot, requires udev/uevent notifications");
                return;
        }

        ASSERT_OK(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, 0, LO_FLAGS_PARTSCAN, LOCK_EX, &loop));

#if HAVE_BLKID
        ASSERT_OK(dissect_loop_device(
                                  loop,
                                  /* verity= */ NULL,
                                  /* mount_options= */ NULL,
                                  /* image_policy= */ NULL,
                                  /* image_filter= */ NULL,
                                  DISSECT_IMAGE_ADD_PARTITION_DEVICES|DISSECT_IMAGE_PIN_PARTITION_DEVICES,
                                  &dissected));
        verify_dissected_image(dissected);

        FOREACH_STRING(fs, "vfat", "ext4") {
                if (ASSERT_OK(mkfs_exists(fs)) == 0) {
                        log_tests_skipped("mkfs.{vfat|ext4} not installed");
                        return;
                }
        }

        ASSERT_OK(sd_id128_randomize(&id));
        ASSERT_OK(make_filesystem(dissected->partitions[PARTITION_ESP].node, "vfat", "EFI", NULL, id, MKFS_DISCARD, 0, NULL, NULL, NULL));

        ASSERT_OK(sd_id128_randomize(&id));
        ASSERT_OK(make_filesystem(dissected->partitions[PARTITION_XBOOTLDR].node, "vfat", "xbootldr", NULL, id, MKFS_DISCARD, 0, NULL, NULL, NULL));

        ASSERT_OK(sd_id128_randomize(&id));
        ASSERT_OK(make_filesystem(dissected->partitions[PARTITION_ROOT].node, "ext4", "root", NULL, id, MKFS_DISCARD, 0, NULL, NULL, NULL));

        ASSERT_OK(sd_id128_randomize(&id));
        ASSERT_OK(make_filesystem(dissected->partitions[PARTITION_HOME].node, "ext4", "home", NULL, id, MKFS_DISCARD, 0, NULL, NULL, NULL));

        dissected = dissected_image_unref(dissected);

        /* We created the file systems now via the per-partition block devices. But the dissection code might
         * probe them via the whole block device. These block devices have separate buffer caches though,
         * hence what was written via the partition device might not appear on the whole block device
         * yet. Let's hence explicitly flush the whole block device, so that the read-back definitely
         * works. */
        ASSERT_OK_ERRNO(ioctl(loop->fd, BLKFLSBUF, 0));

        /* Try to read once, without pinning or adding partitions, i.e. by only accessing the whole block
         * device. */
        ASSERT_OK(dissect_loop_device(
                                  loop,
                                  /* verity= */ NULL,
                                  /* mount_options= */ NULL,
                                  /* image_policy= */ NULL,
                                  /* image_filter= */ NULL,
                                  /* flags= */ 0,
                                  &dissected));
        verify_dissected_image_harder(dissected);
        dissected = dissected_image_unref(dissected);

        /* Now go via the loopback device after all, but this time add/pin, because now we want to mount it. */
        ASSERT_OK(dissect_loop_device(
                                  loop,
                                  /* verity= */ NULL,
                                  /* mount_options= */ NULL,
                                  /* image_policy= */ NULL,
                                  /* image_filter= */ NULL,
                                  DISSECT_IMAGE_ADD_PARTITION_DEVICES|DISSECT_IMAGE_PIN_PARTITION_DEVICES,
                                  &dissected));
        verify_dissected_image_harder(dissected);

        ASSERT_OK(mkdtemp_malloc(NULL, &mounted));

        /* We are particularly correct here, and now downgrade LOCK → LOCK_SH. That's because we are done
         * with formatting the file systems, so we don't need the exclusive lock anymore. From now on a
         * shared one is fine. This way udev can now probe the device if it wants, but still won't call
         * BLKRRPART on it, and that's good, because that would destroy our partition table while we are at
         * it. */
        ASSERT_OK(loop_device_flock(loop, LOCK_SH));

        /* This is a test for the loopback block device setup code and it's use by the image dissection
         * logic: since the kernel APIs are hard use and prone to races, let's test this in a heavy duty
         * test: we open a bunch of threads and repeatedly allocate and deallocate loopback block devices in
         * them in parallel, with an image file with a number of partitions. */
        ASSERT_OK(detach_mount_namespace());

        /* This first (writable) mount will initialize the mount point dirs, so that the subsequent read-only ones can work */
        ASSERT_OK(dissected_image_mount(
                                  dissected,
                                  mounted,
                                  /* uid_shift= */ UID_INVALID,
                                  /* uid_range= */ UID_INVALID,
                                  /* userns_fd= */ -EBADF,
                                  0));

        /* Now we mounted everything, the partitions are pinned. Now it's fine to release the lock
         * fully. This means udev could now issue BLKRRPART again, but that's OK given this will fail because
         * we now mounted the device. */
        ASSERT_OK(loop_device_flock(loop, LOCK_UN));

        ASSERT_OK(umount_recursive(mounted, 0));
        loop = loop_device_unref(loop);

        log_notice("Threads are being started now");

        /* zero timeout means pick default: let's make sure we run for 10s on slow systems at max */
        if (arg_timeout == 0)
                arg_timeout = slow_tests_enabled() ? 5 * USEC_PER_SEC : 1 * USEC_PER_SEC;

        end = usec_add(now(CLOCK_MONOTONIC), arg_timeout);

        if (arg_n_threads > 1)
                for (unsigned i = 0; i < arg_n_threads; i++)
                        ASSERT_EQ(pthread_create(threads + i, NULL, thread_func, FD_TO_PTR(fd)), 0);

        log_notice("All threads started now.");

        if (arg_n_threads == 1)
                ASSERT_NULL(thread_func(FD_TO_PTR(fd)));
        else
                for (unsigned i = 0; i < arg_n_threads; i++) {
                        log_notice("Joining thread #%u.", i);

                        void *k;
                        ASSERT_EQ(pthread_join(threads[i], &k), 0);
                        ASSERT_NULL(k);

                        log_notice("Joined thread #%u.", i);
                }

        log_notice("Threads are all terminated now.");
#else
        log_notice("Cutting test short, since we do not have libblkid.");
#endif
}

static int make_test_image(int *ret_fd) {
        _cleanup_free_ char *p = NULL, *cmd = NULL;
        _cleanup_pclose_ FILE *sfdisk = NULL;

        ASSERT_OK(tempfn_random_child("/var/tmp", "sfdisk", &p));
        int fd = ASSERT_OK_ERRNO(open(p, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW, 0666));
        ASSERT_OK_ERRNO(ftruncate(fd, 256*1024*1024));

        cmd = ASSERT_NOT_NULL(strjoin("sfdisk ", p));
        sfdisk = ASSERT_NOT_NULL(popen(cmd, "we"));

        fputs("label: gpt\n"
              "size=32M, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B\n", sfdisk);

        ASSERT_EQ(pclose(sfdisk), 0);
        sfdisk = NULL;

        (void) unlink(p);

        *ret_fd = fd;
        return 0;
}

TEST(sector_size_regular_file) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_close_ int fd = -EBADF;

        if (have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                log_tests_skipped("not running privileged");
                return;
        }

        if (detect_container() != 0 || running_in_chroot() != 0) {
                log_tests_skipped("Test not supported in a container/chroot");
                return;
        }

        ASSERT_OK(make_test_image(&fd));

        /* sector_size=0 on regular file: should default to 512 */
        ASSERT_OK(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, 0, 0, LOCK_EX, &loop));
        ASSERT_EQ(loop->sector_size, 512u);
        loop = loop_device_unref(loop);

        /* sector_size=UINT32_MAX on regular file with GPT: should probe and find 512 */
        ASSERT_OK(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, UINT32_MAX, 0, LOCK_EX, &loop));
        ASSERT_EQ(loop->sector_size, 512u);
        loop = loop_device_unref(loop);

        /* Explicit sector_size=512 on regular file */
        ASSERT_OK(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, 512, 0, LOCK_EX, &loop));
        ASSERT_EQ(loop->sector_size, 512u);
        loop = loop_device_unref(loop);

        /* Explicit sector_size=4096 on regular file */
        ASSERT_OK(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, 4096, 0, LOCK_EX, &loop));
        ASSERT_EQ(loop->sector_size, 4096u);
        loop = loop_device_unref(loop);
}

TEST(sector_size_block_device) {
        _cleanup_(loop_device_unrefp) LoopDevice *block_loop = NULL, *loop = NULL;
        _cleanup_close_ int fd = -EBADF;

        if (have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                log_tests_skipped("not running privileged");
                return;
        }

        if (detect_container() != 0 || running_in_chroot() != 0) {
                log_tests_skipped("Test not supported in a container/chroot, requires udev/uevent notifications");
                return;
        }

        ASSERT_OK(make_test_image(&fd));

        /* Create a loop device to use as our block device */
        ASSERT_OK(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, 0, LO_FLAGS_PARTSCAN, LOCK_EX, &block_loop));
        ASSERT_FALSE(LOOP_DEVICE_IS_FOREIGN(block_loop));
        ASSERT_OK(loop_device_flock(block_loop, LOCK_SH));

        uint32_t device_ssz = block_loop->sector_size;

        /* sector_size=0 on block device: should use device directly */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, 0, 0, LOCK_SH, &loop));
        ASSERT_FALSE(loop->created);
        ASSERT_EQ(loop->sector_size, device_ssz);
        loop = loop_device_unref(loop);

        /* sector_size=UINT32_MAX on block device: should probe, match device, use directly */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, UINT32_MAX, 0, LOCK_SH, &loop));
        ASSERT_FALSE(loop->created);
        ASSERT_EQ(loop->sector_size, device_ssz);
        loop = loop_device_unref(loop);

        /* sector_size=UINT32_MAX with LO_FLAGS_PARTSCAN: should probe, match, use directly */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, UINT32_MAX, LO_FLAGS_PARTSCAN, LOCK_SH, &loop));
        ASSERT_FALSE(loop->created);
        ASSERT_EQ(loop->sector_size, device_ssz);
        loop = loop_device_unref(loop);

        /* Explicit sector_size matching device: should use device directly */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, device_ssz, 0, LOCK_SH, &loop));
        ASSERT_FALSE(loop->created);
        ASSERT_EQ(loop->sector_size, device_ssz);
        loop = loop_device_unref(loop);

        /* Explicit sector_size=4096 (differs from device 512): should create a real loop device */
        if (device_ssz != 4096) {
                ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, 4096, 0, LOCK_SH, &loop));
                ASSERT_TRUE(loop->created);
                ASSERT_EQ(loop->sector_size, 4096u);
                loop = loop_device_unref(loop);
        }
}

TEST(sector_size_mismatch) {
        _cleanup_(loop_device_unrefp) LoopDevice *block_loop = NULL, *loop = NULL;
        _cleanup_close_ int fd = -EBADF;

        if (have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                log_tests_skipped("not running privileged");
                return;
        }

        if (detect_container() != 0 || running_in_chroot() != 0) {
                log_tests_skipped("Test not supported in a container/chroot");
                return;
        }

        /* Create an image with a GPT written at 512-byte sectors, then create a loop device with
         * 4096-byte sectors on top. This simulates the CD-ROM scenario where the device has large
         * blocks but the GPT uses 512-byte sectors. */
        ASSERT_OK(make_test_image(&fd));

        /* Create a loop device with 4096-byte sector size — GPT was written at 512 */
        ASSERT_OK(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, 4096, 0, LOCK_EX, &block_loop));
        ASSERT_TRUE(block_loop->created);
        ASSERT_EQ(block_loop->sector_size, 4096u);
        ASSERT_OK(loop_device_flock(block_loop, LOCK_SH));

        /* sector_size=0: no preference, should use block device directly despite GPT mismatch */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, 0, 0, LOCK_SH, &loop));
        ASSERT_FALSE(loop->created);
        ASSERT_EQ(loop->sector_size, 4096u);
        loop = loop_device_unref(loop);

        /* sector_size=UINT32_MAX: should probe GPT at 512, detect mismatch with device 4096,
         * and create a new loop device with 512-byte sectors */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, UINT32_MAX, 0, LOCK_SH, &loop));
        ASSERT_TRUE(loop->created);
        ASSERT_EQ(loop->sector_size, 512u);
        loop = loop_device_unref(loop);

        /* Explicit sector_size=512: differs from device 4096, should create a new loop device */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, 512, 0, LOCK_SH, &loop));
        ASSERT_TRUE(loop->created);
        ASSERT_EQ(loop->sector_size, 512u);
        loop = loop_device_unref(loop);

        /* Explicit sector_size=4096: matches device, should use directly */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, 4096, 0, LOCK_SH, &loop));
        ASSERT_FALSE(loop->created);
        ASSERT_EQ(loop->sector_size, 4096u);
        loop = loop_device_unref(loop);
}

TEST(partscan_required) {
        _cleanup_(loop_device_unrefp) LoopDevice *block_loop = NULL, *loop = NULL;
        _cleanup_close_ int fd = -EBADF;

        if (have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                log_tests_skipped("not running privileged");
                return;
        }

        if (detect_container() != 0 || running_in_chroot() != 0) {
                log_tests_skipped("Test not supported in a container/chroot, requires udev/uevent notifications");
                return;
        }

        ASSERT_OK(make_test_image(&fd));

        /* Set up a backing loop device without LO_FLAGS_PARTSCAN. */
        ASSERT_OK(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, 0, 0, LOCK_EX, &block_loop));
        ASSERT_TRUE(block_loop->created);
        ASSERT_OK(loop_device_flock(block_loop, LOCK_SH));

        /* Without LO_FLAGS_PARTSCAN: shortcut should be taken (reuse existing loop). */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, 0, 0, LOCK_SH, &loop));
        ASSERT_FALSE(loop->created);
        loop = loop_device_unref(loop);

        /* With LO_FLAGS_PARTSCAN: backing loop has partscan disabled, so a new loop device with
         * partscan must be created. */
        ASSERT_OK(loop_device_make(block_loop->fd, O_RDWR, 0, UINT64_MAX, 0, LO_FLAGS_PARTSCAN, LOCK_SH, &loop));
        ASSERT_TRUE(loop->created);
        loop = loop_device_unref(loop);
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
