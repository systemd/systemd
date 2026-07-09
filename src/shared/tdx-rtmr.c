/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

#include "sd-id128.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "log.h"
#include "measurement-log.h"
#include "tdx-rtmr.h"
#include "time-util.h"

static const char* tdx_rtmr_sysfs_dir(void) {
        return secure_getenv("SYSTEMD_TDX_MEASUREMENTS_PATH") ?: TDX_RTMR_SYSFS_DIR;
}

static const char* cc_userspace_log_path(void) {
        return secure_getenv("SYSTEMD_MEASURE_LOG_CC_USERSPACE") ?: "/run/log/systemd/cc-measure.log";
}

bool tdx_rtmr_supported(void) {
        return access(tdx_rtmr_sysfs_dir(), F_OK) >= 0;
}

int tdx_rtmr_extend_digest(
                unsigned rtmr,
                const struct iovec *digest,
                unsigned pcr_index,  /* UINT_MAX to omit from the record */
                const char *nv_index_name,
                UserspaceMeasurementEventType event,
                const char *description) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = NULL;
        _cleanup_free_ char *rtmr_path = NULL;
        _cleanup_close_ int rtmr_fd = -EBADF, cc_log_fd = -EBADF;
        sd_id128_t boot_id;
        int r;

        assert(rtmr <= 3);
        assert(iovec_is_set(digest));
        assert(digest->iov_len == TDX_RTMR_DIGEST_SIZE);

        r = asprintf(&rtmr_path, "%s/rtmr%u:sha384", tdx_rtmr_sysfs_dir(), rtmr);
        if (r < 0)
                return log_oom_debug();

        /* Lock the log before extending, so that the record order matches the extend order. */
        cc_log_fd = measurement_log_open(cc_userspace_log_path());

        rtmr_fd = open(rtmr_path, O_WRONLY|O_CLOEXEC|O_NOCTTY);
        if (rtmr_fd < 0) {
                /* Report a missing attribute as -ENXIO: callers reserve -ENOENT for "no such NvPCR"
                 * (see the io.systemd.PCRExtend Varlink error mapping in systemd-pcrextend). */
                if (errno == ENOENT)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENXIO),
                                               "RTMR sysfs attribute '%s' does not exist.", rtmr_path);
                return log_debug_errno(errno, "Failed to open '%s': %m", rtmr_path);
        }

        bool reset_marker = measurement_log_dirty(cc_log_fd) >= 0;

        /* The kernel accepts only a single write() of exactly the digest size at offset zero, anything
         * else is rejected with EINVAL. Hence don't retry on short writes. */
        ssize_t n = write(rtmr_fd, digest->iov_base, digest->iov_len);
        if (n < 0)
                return log_debug_errno(errno, "Failed to extend RTMR %u: %m", rtmr);
        if ((size_t) n != digest->iov_len)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Short write while extending RTMR %u.", rtmr);

        /* From here on everything is best-effort: the register has been extended, hence report success
         * even if writing the record fails. The log's dirty marker then remains set, marking the log as
         * unable to explain the register state. */

        if (cc_log_fd < 0)
                return 0;

        r = sd_id128_get_boot(&boot_id);
        if (r < 0) {
                log_debug_errno(r, "Failed to acquire boot ID, not writing measurement log record: %m");
                return 0;
        }

        r = sd_json_buildo(
                        &record,
                        SD_JSON_BUILD_PAIR("rtmr", SD_JSON_BUILD_UNSIGNED(rtmr)),
                        SD_JSON_BUILD_PAIR_CONDITION(pcr_index != UINT_MAX, "mapped_pcr", SD_JSON_BUILD_UNSIGNED(pcr_index)),
                        SD_JSON_BUILD_PAIR("digests", SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_STRING("hashAlg", "sha384"),
                                                        SD_JSON_BUILD_PAIR_HEX("digest", digest->iov_base, digest->iov_len)))),
                        SD_JSON_BUILD_PAIR_STRING("content_type", "systemd"),
                        SD_JSON_BUILD_PAIR("content", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_CONDITION(!!nv_index_name, "nvIndexName", SD_JSON_BUILD_STRING(nv_index_name)),
                                        SD_JSON_BUILD_PAIR_CONDITION(!!description, "string", SD_JSON_BUILD_STRING(description)),
                                        SD_JSON_BUILD_PAIR_ID128("bootId", boot_id),
                                        SD_JSON_BUILD_PAIR_UNSIGNED("timestamp", now(CLOCK_BOOTTIME)),
                                        SD_JSON_BUILD_PAIR_CONDITION(event >= 0, "eventType", SD_JSON_BUILD_STRING(userspace_measurement_event_type_to_string(event))))));
        if (r < 0) {
                log_debug_errno(r, "Failed to build measurement log record, not writing it: %m");
                return 0;
        }

        (void) measurement_log_append(cc_log_fd, record, reset_marker);
        return 0;
}

int tdx_pcr_to_rtmr_index(uint32_t pcr) {
        /* UEFI 2.10 §38.4.1, the same table TDVF implements for
         * EFI_CC_MEASUREMENT_PROTOCOL.MapPcrToMrIndex(). */

        if (pcr == 0)
                return -EOPNOTSUPP; /* maps to MRTD, not runtime-extendable */
        if (IN_SET(pcr, 1, 7))
                return 0;
        if (pcr >= 2 && pcr <= 6)
                return 1;
        if (pcr >= 8 && pcr <= 15)
                return 2;
        if (pcr <= 23)
                return -EOPNOTSUPP; /* PCRs 16…23 have no defined mapping */
        return -EINVAL;
}
