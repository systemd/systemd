/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/loop.h>
#include <pthread.h>

#include "alloc-util.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "gpt.h"
#include "missing_loop.h"
#include "mkfs-util.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "virt.h"

#define N_THREADS 5
#define N_ITERATIONS 3

static usec_t end = 0;

static void* thread_func(void *ptr) {
        int fd = PTR_TO_FD(ptr);
        int r;

        for (unsigned i = 0; i < N_ITERATIONS; i++) {
                _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
                _cleanup_(umount_and_rmdir_and_freep) char *mounted = NULL;
                _cleanup_(dissected_image_unrefp) DissectedImage *dissected = NULL;

                if (now(CLOCK_MONOTONIC) >= end) {
                        log_notice("Time's up, exiting thread's loop");
                        break;
                }

                log_notice("> Thread iteration #%u.", i);

                assert_se(mkdtemp_malloc(NULL, &mounted) >= 0);

                r = loop_device_make(fd, O_RDONLY, 0, UINT64_MAX, LO_FLAGS_PARTSCAN, &loop);
                if (r < 0)
                        log_error_errno(r, "Failed to allocate loopback device: %m");
                assert_se(r >= 0);

                log_notice("Acquired loop device %s, will mount on %s", loop->node, mounted);

                r = dissect_image(loop->fd, NULL, NULL, DISSECT_IMAGE_READ_ONLY, &dissected);
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

                assert_se(dissected->partitions[PARTITION_ESP].found);
                assert_se(dissected->partitions[PARTITION_ESP].node);
                assert_se(dissected->partitions[PARTITION_XBOOTLDR].found);
                assert_se(dissected->partitions[PARTITION_XBOOTLDR].node);
                assert_se(dissected->partitions[PARTITION_ROOT].found);
                assert_se(dissected->partitions[PARTITION_ROOT].node);
                assert_se(dissected->partitions[PARTITION_HOME].found);
                assert_se(dissected->partitions[PARTITION_HOME].node);

                r = dissected_image_mount(dissected, mounted, UID_INVALID, DISSECT_IMAGE_READ_ONLY);
                log_notice_errno(r, "Mounted %s → %s: %m", loop->node, mounted);
                assert_se(r >= 0);

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

static bool have_root_gpt_type(void) {
#ifdef GPT_ROOT_NATIVE
        return true;
#else
        return false;
#endif
}

int main(int argc, char *argv[]) {
        _cleanup_free_ char *p = NULL, *cmd = NULL;
        _cleanup_(pclosep) FILE *sfdisk = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_close_ int fd = -1;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted = NULL;
        pthread_t threads[N_THREADS];
        const char *fs;
        sd_id128_t id;
        int r;

        test_setup_logging(LOG_DEBUG);
        log_show_tid(true);
        log_show_time(true);

        if (!have_root_gpt_type()) {
                log_tests_skipped("No root partition GPT defined for this architecture, exiting.");
                return EXIT_TEST_SKIP;
        }

        if (detect_container() > 0) {
                log_tests_skipped("Test not supported in a container, requires udev/uevent notifications.");
                return EXIT_TEST_SKIP;
        }

        if (strstr_ptr(ci_environment(), "autopkgtest") || strstr_ptr(ci_environment(), "github-actions")) {
                // FIXME: we should reenable this one day
                log_tests_skipped("Skipping test on Ubuntu autopkgtest CI/GH Actions, test too slow and installed udev too flakey.");
                return EXIT_TEST_SKIP;
        }

        /* This is a test for the loopback block device setup code and it's use by the image dissection
         * logic: since the kernel APIs are hard use and prone to races, let's test this in a heavy duty
         * test: we open a bunch of threads and repeatedly allocate and deallocate loopback block devices in
         * them in parallel, with an image file with a number of partitions. */

        r = detach_mount_namespace();
        if (ERRNO_IS_PRIVILEGE(r)) {
                log_tests_skipped("Lacking privileges");
                return EXIT_TEST_SKIP;
        }

        FOREACH_STRING(fs, "vfat", "ext4") {
                r = mkfs_exists(fs);
                assert_se(r >= 0);
                if (!r) {
                        log_tests_skipped("mkfs.{vfat|ext4} not installed");
                        return EXIT_TEST_SKIP;
                }
        }

        assert_se(r >= 0);

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

#ifdef GPT_ROOT_NATIVE
        fprintf(sfdisk, SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(GPT_ROOT_NATIVE));
#else
        fprintf(sfdisk, SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(GPT_ROOT_X86_64));
#endif

        fputs("\n"
              "size=32M, type=933AC7E1-2EB4-4F13-B844-0E14E2AEF915\n", sfdisk);

        assert_se(pclose(sfdisk) == 0);
        sfdisk = NULL;

        assert_se(loop_device_make(fd, O_RDWR, 0, UINT64_MAX, LO_FLAGS_PARTSCAN, &loop) >= 0);
        assert_se(dissect_image(loop->fd, NULL, NULL, 0, &dissected) >= 0);

        assert_se(dissected->partitions[PARTITION_ESP].found);
        assert_se(dissected->partitions[PARTITION_ESP].node);
        assert_se(dissected->partitions[PARTITION_XBOOTLDR].found);
        assert_se(dissected->partitions[PARTITION_XBOOTLDR].node);
        assert_se(dissected->partitions[PARTITION_ROOT].found);
        assert_se(dissected->partitions[PARTITION_ROOT].node);
        assert_se(dissected->partitions[PARTITION_HOME].found);
        assert_se(dissected->partitions[PARTITION_HOME].node);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(make_filesystem(dissected->partitions[PARTITION_ESP].node, "vfat", "EFI", id, true) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(make_filesystem(dissected->partitions[PARTITION_XBOOTLDR].node, "vfat", "xbootldr", id, true) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(make_filesystem(dissected->partitions[PARTITION_ROOT].node, "ext4", "root", id, true) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(make_filesystem(dissected->partitions[PARTITION_HOME].node, "ext4", "home", id, true) >= 0);

        dissected = dissected_image_unref(dissected);
        assert_se(dissect_image(loop->fd, NULL, NULL, 0, &dissected) >= 0);

        assert_se(mkdtemp_malloc(NULL, &mounted) >= 0);

        /* This first (writable) mount will initialize the mount point dirs, so that the subsequent read-only ones can work */
        assert_se(dissected_image_mount(dissected, mounted, UID_INVALID, 0) >= 0);

        assert_se(umount_recursive(mounted, 0) >= 0);
        loop = loop_device_unref(loop);

        log_notice("Threads are being started now");

        /* Let's make sure we run for 10s on slow systems at max */
        end = usec_add(now(CLOCK_MONOTONIC),
                       slow_tests_enabled() ? 5 * USEC_PER_SEC :
                       1 * USEC_PER_SEC);

        for (unsigned i = 0; i < N_THREADS; i++)
                assert_se(pthread_create(threads + i, NULL, thread_func, FD_TO_PTR(fd)) == 0);

        log_notice("All threads started now.");

        for (unsigned i = 0; i < N_THREADS; i++) {
                log_notice("Joining thread #%u.", i);

                void *k;
                assert_se(pthread_join(threads[i], &k) == 0);
                assert_se(k == NULL);

                log_notice("Joined thread #%u.", i);
        }

        log_notice("Threads are all terminated now.");

        return 0;
}
