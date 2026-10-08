/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nvme_ioctl.h>
#include <sys/ioctl.h>

#include "log.h"
#include "report-diskhealth-nvme.h"
#include "time-util.h"
#include "unaligned.h"

/* See NVM Express Base Specification, section "SMART / Health Information (Log Page Identifier 02h)" */
#define NVME_ADMIN_GET_LOG_PAGE 0x02U
#define NVME_LOG_SMART 0x02U
#define NVME_NSID_ALL UINT32_C(0xFFFFFFFF)
#define NVME_SMART_LOG_SIZE 512U
#define NVME_COMMAND_TIMEOUT_MSEC (5U * MSEC_PER_SEC)

#define NVME_SMART_CRITICAL_WARNING_OFFSET  0U
#define NVME_SMART_AVAILABLE_SPARE_OFFSET   3U
#define NVME_SMART_PERCENTAGE_USED_OFFSET   5U
#define NVME_SMART_POWER_CYCLES_OFFSET    112U
#define NVME_SMART_POWER_ON_HOURS_OFFSET  128U
#define NVME_SMART_MEDIA_ERRORS_OFFSET    160U

static uint64_t read_le128_saturated(const uint8_t *p) {
        /* The counters in the log page are 128-bit little endian values. Nothing will ever get anywhere near
         * 2^64 in practice, but let's saturate instead of truncating, just in case. Note that we saturate to
         * UINT64_MAX-1, since UINT64_MAX is used as "unavailable" marker. */
        uint64_t v = unaligned_read_le64(p);
        return unaligned_read_le64(p + 8) != 0 ? UINT64_MAX - 1 : MIN(v, UINT64_MAX - 1);
}

int nvme_read_health(int fd, NVMeHealth *ret) {
        int r;

        assert(fd >= 0);
        assert(ret);

        uint8_t log[NVME_SMART_LOG_SIZE] _alignas_(uint64_t) = {};
        struct nvme_admin_cmd cmd = {
                .opcode = NVME_ADMIN_GET_LOG_PAGE,
                /* Request the controller-wide log, rather than the per-namespace one, which controllers
                 * are not required to support. */
                .nsid = NVME_NSID_ALL,
                .addr = (uintptr_t) log,
                .data_len = sizeof(log),
                /* Bits 7:0: log page identifier, bits 31:16: lower 16 bits of the number of dwords to read,
                 * 0's based */
                .cdw10 = NVME_LOG_SMART | ((sizeof(log) / 4 - 1) << 16),
                .timeout_ms = NVME_COMMAND_TIMEOUT_MSEC,
        };

        /* Note that the ioctl returns the NVMe status code as positive value if the controller failed the
         * command, and a negative errno if the command could not be submitted at all. */
        r = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
        if (r < 0)
                return log_debug_errno(errno, "Failed to issue NVMe Get Log Page command: %m");
        if (r > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "NVMe Get Log Page command failed with status 0x%x.", (unsigned) r);

        *ret = (NVMeHealth) {
                .critical_warning = log[NVME_SMART_CRITICAL_WARNING_OFFSET],
                .available_spare = log[NVME_SMART_AVAILABLE_SPARE_OFFSET],
                .percentage_used = log[NVME_SMART_PERCENTAGE_USED_OFFSET],
                .media_errors = read_le128_saturated(log + NVME_SMART_MEDIA_ERRORS_OFFSET),
                .power_cycles = read_le128_saturated(log + NVME_SMART_POWER_CYCLES_OFFSET),
                .power_on_hours = read_le128_saturated(log + NVME_SMART_POWER_ON_HOURS_OFFSET),
        };

        return 0;
}
