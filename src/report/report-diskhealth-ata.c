/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <scsi/sg.h>
#include <sys/ioctl.h>

#include "log.h"
#include "report-diskhealth-ata.h"
#include "time-util.h"
#include "unaligned.h"

/* ATA commands are issued via the SCSI/ATA Translation (SAT) ATA PASS-THROUGH (16) command, see T10 SAT-3,
 * which libata implements for SATA disks. The ATA commands and data structures used are described in T13
 * ACS-3 (ATA/ATAPI Command Set). */

#define ATA_PASS_THROUGH_16 0x85U
#define ATA_PROTOCOL_NON_DATA 3U
#define ATA_PROTOCOL_PIO_DATA_IN 4U
#define ATA_FLAG_CK_COND (1U << 5)                      /* Return ATA registers as sense data */
#define ATA_FLAG_T_DIR_IN (1U << 3)                     /* Transfer from device */
#define ATA_FLAG_BYTE_BLOCK (1U << 2)                   /* Transfer length is in blocks */
#define ATA_FLAG_T_LENGTH_COUNT 2U                      /* Transfer length is in the COUNT field */

#define ATA_CMD_CHECK_POWER_MODE 0xE5U
#define ATA_CMD_READ_LOG_EXT 0x2FU
#define ATA_CMD_SMART 0xB0U
#define ATA_SMART_READ_DATA 0xD0U
#define ATA_SMART_RETURN_STATUS 0xDAU
#define ATA_SMART_LBA_MID 0x4FU
#define ATA_SMART_LBA_HIGH 0xC2U
#define ATA_SMART_LBA_MID_FAILING 0xF4U
#define ATA_SMART_LBA_HIGH_FAILING 0x2CU

#define ATA_STATUS_ERR 0x01U
#define ATA_STATUS_DF 0x20U

#define ATA_SECTOR_SIZE 512U
#define ATA_COMMAND_TIMEOUT_MSEC (5U * MSEC_PER_SEC)

#define ATA_SMART_ATTRIBUTE_REALLOCATED_SECTORS 5U
#define ATA_SMART_ATTRIBUTE_PENDING_SECTORS 197U
#define ATA_SMART_ATTRIBUTE_OFFLINE_UNCORRECTABLE 198U
#define ATA_SMART_ATTRIBUTES_OFFSET 2U
#define ATA_SMART_ATTRIBUTES_MAX 30U
#define ATA_SMART_ATTRIBUTE_SIZE 12U

#define ATA_LOG_DEVICE_STATISTICS 0x04U
#define ATA_DEVSTAT_PAGE_GENERAL 0x01U
#define ATA_DEVSTAT_POWER_CYCLES_OFFSET 8U
#define ATA_DEVSTAT_POWER_ON_HOURS_OFFSET 16U
#define ATA_DEVSTAT_SUPPORTED (UINT64_C(1) << 63)
#define ATA_DEVSTAT_VALID (UINT64_C(1) << 62)

#define SCSI_STATUS_GOOD 0x00U
#define SCSI_STATUS_CHECK_CONDITION 0x02U
#define SCSI_SENSE_KEY_RECOVERED_ERROR 0x01U
#define SCSI_ASC_ATA_PASS_THROUGH_INFORMATION 0x00U
#define SCSI_ASCQ_ATA_PASS_THROUGH_INFORMATION 0x1DU
#define SCSI_SENSE_DESCRIPTOR_ATA_STATUS_RETURN 0x09U

typedef struct ATARegisters {
        uint8_t error;
        uint8_t status;
        uint8_t count;
        uint8_t lba_low;
        uint8_t lba_mid;
        uint8_t lba_high;
} ATARegisters;

static int ata_parse_sense(const uint8_t *sense, size_t sense_len, ATARegisters *ret) {
        ATARegisters regs;
        uint8_t key, asc, ascq;

        assert(sense);
        assert(ret);

        /* With CK_COND set the SATL returns the ATA output registers in the sense data, which comes either in
         * descriptor format (as ATA Status Return descriptor) or in fixed format, depending on the D_SENSE
         * bit in the control mode page. libata defaults to the latter, but let's handle both. */

        if (sense_len < 8)
                return -EBADMSG;

        switch (sense[0] & 0x7f) {

        case 0x72: { /* Descriptor format */
                key = sense[1] & 0x0f;
                asc = sense[2];
                ascq = sense[3];

                size_t end = MIN(sense_len, 8 + (size_t) sense[7]);
                const uint8_t *d = NULL;
                for (size_t i = 8; i + 2 <= end && sense[i + 1] > 0; i += 2 + sense[i + 1])
                        if (sense[i] == SCSI_SENSE_DESCRIPTOR_ATA_STATUS_RETURN && sense[i + 1] >= 0x0c && i + 14 <= end) {
                                d = sense + i;
                                break;
                        }
                if (!d)
                        return -EBADMSG;

                regs = (ATARegisters) {
                        .error = d[3],
                        .count = d[5],
                        .lba_low = d[7],
                        .lba_mid = d[9],
                        .lba_high = d[11],
                        .status = d[13],
                };
                break;
        }

        case 0x70: /* Fixed format */
                if (sense_len < 14)
                        return -EBADMSG;

                key = sense[2] & 0x0f;
                asc = sense[12];
                ascq = sense[13];

                regs = (ATARegisters) {
                        .error = sense[3],
                        .status = sense[4],
                        .count = sense[6],
                        .lba_low = sense[9],
                        .lba_mid = sense[10],
                        .lba_high = sense[11],
                };
                break;

        default:
                return -EBADMSG;
        }

        if (key != SCSI_SENSE_KEY_RECOVERED_ERROR ||
            asc != SCSI_ASC_ATA_PASS_THROUGH_INFORMATION ||
            ascq != SCSI_ASCQ_ATA_PASS_THROUGH_INFORMATION)
                return -EIO;

        *ret = regs;
        return 0;
}

static int ata_pass_through(
                int fd,
                bool extend,
                uint8_t command,
                uint8_t features,
                uint8_t count,
                uint8_t lba_low,
                uint8_t lba_mid,
                uint8_t lba_high,
                void *buf,
                size_t buf_len,
                ATARegisters *ret_registers) {

        int r;

        assert(fd >= 0);
        assert(!buf == (buf_len == 0));
        assert(buf_len % ATA_SECTOR_SIZE == 0);

        /* Only the low bytes of the 48-bit registers are used here. Data transfers are PIO Data-In of
         * 'count' sectors, commands without data buffer are non-data commands. If the output registers are
         * requested, CK_COND is set to make the SATL return them. */
        uint8_t cdb[16] = {
                [0] = ATA_PASS_THROUGH_16,
                [1] = ((buf ? ATA_PROTOCOL_PIO_DATA_IN : ATA_PROTOCOL_NON_DATA) << 1) | extend,
                [2] = (ret_registers ? ATA_FLAG_CK_COND : 0) |
                      (buf ? ATA_FLAG_T_DIR_IN | ATA_FLAG_BYTE_BLOCK | ATA_FLAG_T_LENGTH_COUNT : 0),
                [4] = features,
                [6] = count,
                [8] = lba_low,
                [10] = lba_mid,
                [12] = lba_high,
                [14] = command,
        };
        uint8_t sense[32] = {};
        struct sg_io_hdr io = {
                .interface_id = 'S',
                .dxfer_direction = buf ? SG_DXFER_FROM_DEV : SG_DXFER_NONE,
                .cmd_len = sizeof(cdb),
                .mx_sb_len = sizeof(sense),
                .dxfer_len = buf_len,
                .dxferp = buf,
                .cmdp = cdb,
                .sbp = sense,
                .timeout = ATA_COMMAND_TIMEOUT_MSEC,
        };

        if (ioctl(fd, SG_IO, &io) < 0)
                return log_debug_errno(errno, "Failed to issue ATA command 0x%02x: %m", command);

        if (io.host_status != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "ATA command 0x%02x failed with host status 0x%x.", command, io.host_status);

        ATARegisters registers = {};
        switch (io.status) {

        case SCSI_STATUS_GOOD:
                /* Without output registers we cannot tell whether the command succeeded, if we asked for
                 * them. */
                if (ret_registers)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "ATA command 0x%02x returned no ATA registers.", command);
                break;

        case SCSI_STATUS_CHECK_CONDITION:
                r = ata_parse_sense(sense, io.sb_len_wr, &registers);
                if (r < 0)
                        return log_debug_errno(r, "ATA command 0x%02x failed: %m", command);

                if (registers.status & (ATA_STATUS_ERR|ATA_STATUS_DF))
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "ATA command 0x%02x failed with status 0x%02x, error 0x%02x.",
                                               command, registers.status, registers.error);
                break;

        default:
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "ATA command 0x%02x failed with SCSI status 0x%02x.", command, io.status);
        }

        if (io.resid != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "ATA command 0x%02x returned short data.", command);

        if (ret_registers)
                *ret_registers = registers;

        return 0;
}

static int ata_check_standby(int fd) {
        ATARegisters registers;
        int r;

        assert(fd >= 0);

        r = ata_pass_through(fd, /* extend= */ false, ATA_CMD_CHECK_POWER_MODE, /* features= */ 0, /* count= */ 0,
                             /* lba_low= */ 0, /* lba_mid= */ 0, /* lba_high= */ 0,
                             /* buf= */ NULL, /* buf_len= */ 0, &registers);
        if (r < 0)
                return r;

        /* 0x00 is Standby (PM2), 0x01 is Standby_y. Everything else is some flavour of idle or active. */
        return IN_SET(registers.count, 0x00, 0x01);
}

static int ata_smart_return_status(int fd) {
        ATARegisters registers;
        int r;

        assert(fd >= 0);

        r = ata_pass_through(fd, /* extend= */ false, ATA_CMD_SMART, ATA_SMART_RETURN_STATUS, /* count= */ 0,
                             /* lba_low= */ 0, ATA_SMART_LBA_MID, ATA_SMART_LBA_HIGH,
                             /* buf= */ NULL, /* buf_len= */ 0, &registers);
        if (r < 0)
                return r;

        if (registers.lba_mid == ATA_SMART_LBA_MID && registers.lba_high == ATA_SMART_LBA_HIGH)
                return false;
        if (registers.lba_mid == ATA_SMART_LBA_MID_FAILING && registers.lba_high == ATA_SMART_LBA_HIGH_FAILING)
                return true;

        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected SMART RETURN STATUS signature 0x%02x/0x%02x.",
                               registers.lba_mid, registers.lba_high);
}

static int ata_smart_read_attributes(int fd, ATAHealth *h) {
        uint8_t data[ATA_SECTOR_SIZE] _alignas_(uint64_t) = {};
        int r;

        assert(fd >= 0);
        assert(h);

        r = ata_pass_through(fd, /* extend= */ false, ATA_CMD_SMART, ATA_SMART_READ_DATA, /* count= */ 1,
                             /* lba_low= */ 0, ATA_SMART_LBA_MID, ATA_SMART_LBA_HIGH,
                             data, sizeof(data), /* ret_registers= */ NULL);
        if (r < 0)
                return r;

        /* The last byte is chosen so that all bytes of the structure sum up to zero */
        uint8_t sum = 0;
        FOREACH_ELEMENT(i, data)
                sum += *i;
        if (sum != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "SMART data checksum mismatch.");

        /* The attribute table is vendor specific in principle, but the three attributes we care about have
         * the same meaning and raw value encoding (48-bit little endian count) on all relevant devices. */
        for (size_t i = 0; i < ATA_SMART_ATTRIBUTES_MAX; i++) {
                const uint8_t *a = data + ATA_SMART_ATTRIBUTES_OFFSET + i * ATA_SMART_ATTRIBUTE_SIZE;
                uint64_t raw = (uint64_t) unaligned_read_le32(a + 5) | ((uint64_t) unaligned_read_le16(a + 9) << 32);

                switch (a[0]) {

                case ATA_SMART_ATTRIBUTE_REALLOCATED_SECTORS:
                        h->reallocated_sectors = raw;
                        break;

                case ATA_SMART_ATTRIBUTE_PENDING_SECTORS:
                        h->pending_sectors = raw;
                        break;

                case ATA_SMART_ATTRIBUTE_OFFLINE_UNCORRECTABLE:
                        h->offline_uncorrectable = raw;
                        break;
                }
        }

        return 0;
}

static int ata_read_device_statistics(int fd, ATAHealth *h) {
        uint8_t page[ATA_SECTOR_SIZE] _alignas_(uint64_t) = {};
        int r;

        assert(fd >= 0);
        assert(h);

        /* Power-on hours and power cycles are read from the General Statistics page of the Device Statistics
         * log, rather than from SMART attributes 9 and 12, since the encoding of the former is standardized,
         * while the latter differs between vendors (some count power-on time in minutes or half-minutes, for
         * example). The page number goes into bits 15:8 of the LBA, i.e. into the LBA mid register. */
        r = ata_pass_through(fd, /* extend= */ true, ATA_CMD_READ_LOG_EXT, /* features= */ 0, /* count= */ 1,
                             ATA_LOG_DEVICE_STATISTICS, ATA_DEVSTAT_PAGE_GENERAL, /* lba_high= */ 0,
                             page, sizeof(page), /* ret_registers= */ NULL);
        if (r < 0)
                return r;

        /* The header's bits 23:16 carry the page number */
        uint64_t header = unaligned_read_le64(page);
        if (((header >> 16) & 0xff) != ATA_DEVSTAT_PAGE_GENERAL)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected Device Statistics page header 0x%016" PRIx64 ".", header);

        /* Each statistic is a quadword, whose top bits flag whether it is supported and currently valid. For
         * both statistics we are interested in the value is in bits 31:0. */
        uint64_t q = unaligned_read_le64(page + ATA_DEVSTAT_POWER_CYCLES_OFFSET);
        if (FLAGS_SET(q, ATA_DEVSTAT_SUPPORTED|ATA_DEVSTAT_VALID))
                h->power_cycles = q & UINT32_MAX;

        q = unaligned_read_le64(page + ATA_DEVSTAT_POWER_ON_HOURS_OFFSET);
        if (FLAGS_SET(q, ATA_DEVSTAT_SUPPORTED|ATA_DEVSTAT_VALID))
                h->power_on_hours = q & UINT32_MAX;

        return 0;
}

int ata_read_health(int fd, ATAHealth *ret) {
        int r;

        assert(fd >= 0);
        assert(ret);

        /* Reading SMART data or logs spins up a disk that is in standby mode, and we should not do that
         * merely for collecting metrics. CHECK POWER MODE does not change the power state, hence query that
         * first. If that fails we cannot tell, hence skip the device too. */
        r = ata_check_standby(fd);
        if (r < 0)
                return r;
        if (r > 0) {
                *ret = ATA_HEALTH_NULL;
                return 0;
        }

        ATAHealth h = ATA_HEALTH_NULL;

        /* The remaining commands are independent of each other, hence if one fails, just skip the metrics
         * it would have provided. The ata_pass_through() already logged about the failure. */
        r = ata_smart_return_status(fd);
        if (r >= 0)
                h.smart_failing = r;

        (void) ata_smart_read_attributes(fd, &h);
        (void) ata_read_device_statistics(fd, &h);

        *ret = h;
        return 1;
}
