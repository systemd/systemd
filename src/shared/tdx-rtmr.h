/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Interface for extending Intel TDX Runtime Measurement Registers (RTMRs) from userspace,
 * via the sysfs interface exposed by the tdx-guest driver since Linux 6.16,
 * see Documentation/ABI/testing/sysfs-devices-virtual-misc-tdx_guest. */

#define TDX_RTMR_SYSFS_DIR "/sys/devices/virtual/misc/tdx_guest/measurements"

/* RTMRs are always SHA-384 */
#define TDX_RTMR_DIGEST_SIZE 48U

/* NvPCR measurements are mapped to RTMR 2. NvPCRs have no UEFI-defined mapping, this is a systemd
 * convention: RTMR 2 carries the other OS-level measurements, while RTMR 3 is by convention owned by
 * the workload. Never mirror NvPCR anchor initialization to RTMRs: its extension value is derived
 * from a secret, and RTMRs need no anchoring as they cannot be deleted and recreated. */
#define TDX_NVPCR_RTMR 2U

/* The firmware CC event log (CCEL ACPI table), the boot-time counterpart of the userspace CC
 * measurement log. */
const char* cc_firmware_log_path(void);

/* Returns true if the kernel exposes the TDX measurement registers via sysfs. */
bool tdx_rtmr_supported(void);

/* Extends the given RTMR with the digest and appends a record to the userspace CC measurement log.
 * Returns -ENXIO if the sysfs attribute doesn't exist, i.e. we're not running as TDX guest or the
 * tdx-guest driver is not available. The log record is best-effort: if writing it fails, the
 * extension is reported as success anyway, and the log's dirty marker is left set (see measurement-log.h).
 * pcr_index and nv_index_name describe what the measurement was mapped from, and only appear in the
 * log record. */
int tdx_rtmr_extend_digest(
                unsigned rtmr,
                const struct iovec *digest,
                unsigned pcr_index,  /* UINT_MAX to omit from the record */
                const char *nv_index_name,
                UserspaceMeasurementEventType event,
                const char *description);

/* Maps a TPM PCR index to the equivalent RTMR, per the fixed table in UEFI spec v2.10 §38.4.1. Returns
 * the RTMR number as used in the sysfs attribute names, one less than the EFI CC MR index. Returns
 * -EOPNOTSUPP for valid PCR indexes without a runtime-extendable equivalent (PCR 0 -> MRTD,
 * PCRs 16..23 unmapped), -EINVAL for values that aren't PCR indexes. */
int tdx_pcr_to_rtmr_index(uint32_t pcr);
