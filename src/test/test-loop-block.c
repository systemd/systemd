/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/loop.h>
#include <pthread.h>
#include <sys/file.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "gpt.h"
#include "main-func.h"
#include "missing_loop.h"
#include "mkfs-util.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "virt.h"

static unsigned arg_n_threads = 5;
static unsigned arg_n_iterations = 3;
static usec_t arg_timeout = 0;

#if HAVE_BLKID
static usec_t end = 0;

static void verify_dissected_image(DissectedImage *dissected) {
        assert_se(dissected->partitions[PARTITION_ESP].found);
        assert_se(dissected->partitions[PARTITION_ESP].node);
        assert_se(dissected->partitions[PARTITION_XBOOTLDR].found);
        assert_se(dissected->partitions[PARTITION_XBOOTLDR].node);
        assert_se(dissected->partitions[PARTITION_ROOT].found);
        assert_se(dissected->partitions[PARTITION_ROOT].node);
        assert_se(dissected->partitions[PARTITION_HOME].found);
        assert_se(dissected->partitions[PARTITION_HOME].node);
}

static void* thread_func(void *ptr) {
        int fd = PTR_TO_FD(ptr);
        int r;

        for (unsigned i = 0; i < arg_n_iterations; i++) {
                _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
                _cleanup_(umount_and_rmdir_and_freep) char *mounted = NULL;
                _cleanup_(dissected_image_unrefp) DissectedImage *dissected = NULL;

                if (now(CLOCK_MONOTONIC) >= end) {
                        log_notice("Time's up, exiting thread's loop");
                        break;
                }

                log_notice("> Thread iteration #%u.", i);

                assert_se(mkdtemp_malloc(NULL, &mounted) >= 0);

                r = loop_device_make(fd, O_RDONLY, 0, UINT64_MAX, 0, LO_FLAGS_PARTSCAN, LOCK_SH, &loop);
                if (r < 0)
                        log_error_errno(r, "Failed to allocate loopback device: %m");
                assert_se(r >= 0);
                assert_se(loop->dev);
                assert_se(loop->backing_file);

                log_notice("Acquired loop device %s, will mount on %s", loop->node, mounted);

                r = dissect_loop_device(loop, NULL, NULL, DISSECT_IMAGE_READ_ONLY|DISSECT_IMAGE_ADD_PARTITION_DEVICES|DISSECT_IMAGE_PIN_PARTITION_DEVICES, &dissected);
                if (r < 0)
                        log_error_errno(r, "Failed dissect loopback device %s: %m", loop->node);
                assert_se(r >= 0);

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

                r = dissected_image_mount(dissected, mounted, UID_INVALID, UID_INVALID, DISSECT_IMAGE_READ_ONLY);
                log_notice_errno(r, "Mounted %s → %s: %m", loop->node, mounted);
                assert_se(r >= 0);

                /* Now the block device is mounted, we don't need no manual lock anymore, the devices are now
                 * pinned by the mounts. */
                assert_se(loop_device_flock(loop, LOCK_UN) >= 0);

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

static int run(int argc, char *argv[]) {
#if HAVE_BLKID
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted = NULL;
        pthread_t threads[arg_n_threads];
        sd_id128_t id;
#endif
        _cleanup_free_ char *p = NULL, *cmd = NULL;
        _cleanup_(pclosep) FILE *sfdisk = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        test_setup_logging(LOG_DEBUG);
        log_show_tid(true);
        log_show_time(true);
        log_show_color(true);

        if (argc >= 2) {
                r = safe_atou(argv[1], &arg_n_threads);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse first argument (number of threads): %s", argv[1]);
                if (arg_n_threads <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Number of threads must be at least 1, refusing.");
        }

        if (argc >= 3) {
                r = safe_atou(argv[2], &arg_n_iterations);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse second argument (number of iterations): %s", argv[2]);
                if (arg_n_iterations <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Number of iterations must be at least 1, refusing.");
        }

        if (argc >= 4) {
                r = parse_sec(argv[3], &arg_timeout);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse third argument (timeout): %s", argv[3]);
        }

        if (argc >= 5)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments (expected 3 at max).");

        if (!have_root_gpt_type())
                return log_tests_skipped("No root partition GPT defined for this architecture");

        r = find_executable("sfdisk", NULL);
        if (r < 0)
                return log_tests_skipped_errno(r, "Could not find sfdisk command");

        assert_se(tempfn_random_child("/var/tmp", "sfdisk", &p) >= 0);
        fd = open(p, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW, 0666);
        assert_se(fd >= 0);
        assert_se(ftruncate(fd, 256*1024*1024) >= 0);

        assert_se(cmd = strjoin("sfdisk ", p));
        assert_se(sfdisk = popen(cmd, "we"));

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

        assert_se(pclose(sfdisk) == 0);
        sfdisk = NULL;

#if HAVE_BLKID
        assert_se(dissect_image_file(p, NULL, NULL, 0, &dissected) >= 0);
        verify_dissected_image(dissected);
        dissected = dissected_image_unref(dissected);
#endif

        if (geteuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0) {
                log_tests_skipped("not running privileged");
                return 0;
        }

        if (detect_container() > 0) {
                log_tests_skipped("Test not supported in a container, requires udev/uevent notifications");
                return 0;
        }

        assert_se(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, 0, LO_FLAGS_PARTSCAN, LOCK_EX, &loop) >= 0);

#if HAVE_BLKID
        assert_se(dissect_loop_device(loop, NULL, NULL, DISSECT_IMAGE_ADD_PARTITION_DEVICES|DISSECT_IMAGE_PIN_PARTITION_DEVICES, &dissected) >= 0);
        verify_dissected_image(dissected);

        FOREACH_STRING(fs, "vfat", "ext4") {
                r = mkfs_exists(fs);
                assert_se(r >= 0);
                if (!r) {
                        log_tests_skipped("mkfs.{vfat|ext4} not installed");
                        return 0;
                }
        }
        assert_se(r >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(make_filesystem(dissected->partitions[PARTITION_ESP].node, "vfat", "EFI", NULL, id, true) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(make_filesystem(dissected->partitions[PARTITION_XBOOTLDR].node, "vfat", "xbootldr", NULL, id, true) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(make_filesystem(dissected->partitions[PARTITION_ROOT].node, "ext4", "root", NULL, id, true) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(make_filesystem(dissected->partitions[PARTITION_HOME].node, "ext4", "home", NULL, id, true) >= 0);

        dissected = dissected_image_unref(dissected);
        assert_se(dissect_loop_device(loop, NULL, NULL, DISSECT_IMAGE_ADD_PARTITION_DEVICES|DISSECT_IMAGE_PIN_PARTITION_DEVICES, &dissected) >= 0);
        verify_dissected_image(dissected);

        assert_se(mkdtemp_malloc(NULL, &mounted) >= 0);

        /* We are particularly correct here, and now downgrade LOCK → LOCK_SH. That's because we are done
         * with formatting the file systems, so we don't need the exclusive lock anymore. From now on a
         * shared one is fine. This way udev can now probe the device if it wants, but still won't call
         * BLKRRPART on it, and that's good, because that would destroy our partition table while we are at
         * it. */
        assert_se(loop_device_flock(loop, LOCK_SH) >= 0);

        /* This is a test for the loopback block device setup code and it's use by the image dissection
         * logic: since the kernel APIs are hard use and prone to races, let's test this in a heavy duty
         * test: we open a bunch of threads and repeatedly allocate and deallocate loopback block devices in
         * them in parallel, with an image file with a number of partitions. */
        assert_se(detach_mount_namespace() >= 0);

        /* This first (writable) mount will initialize the mount point dirs, so that the subsequent read-only ones can work */
        assert_se(dissected_image_mount(dissected, mounted, UID_INVALID, UID_INVALID, 0) >= 0);

        /* Now we mounted everything, the partitions are pinned. Now it's fine to release the lock
         * fully. This means udev could now issue BLKRRPART again, but that's OK given this will fail because
         * we now mounted the device. */
        assert_se(loop_device_flock(loop, LOCK_UN) >= 0);

        assert_se(umount_recursive(mounted, 0) >= 0);
        loop = loop_device_unref(loop);

        log_notice("Threads are being started now");

        /* zero timeout means pick default: let's make sure we run for 10s on slow systems at max */
        if (arg_timeout == 0)
                arg_timeout = slow_tests_enabled() ? 5 * USEC_PER_SEC : 1 * USEC_PER_SEC;

        end = usec_add(now(CLOCK_MONOTONIC), arg_timeout);

        if (arg_n_threads > 1)
                for (unsigned i = 0; i < arg_n_threads; i++)
                        assert_se(pthread_create(threads + i, NULL, thread_func, FD_TO_PTR(fd)) == 0);

        log_notice("All threads started now.");

        if (arg_n_threads == 1)
                assert_se(thread_func(FD_TO_PTR(fd)) == NULL);
        else
                for (unsigned i = 0; i < arg_n_threads; i++) {
                        log_notice("Joining thread #%u.", i);

                        void *k;
                        assert_se(pthread_join(threads[i], &k) == 0);
                        assert_se(!k);

                        log_notice("Joined thread #%u.", i);
                }

        log_notice("Threads are all terminated now.");
#else
        log_notice("Cutting test short, since we do not have libblkid.");
#endif
        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
