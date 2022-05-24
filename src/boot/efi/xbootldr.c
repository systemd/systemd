/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efigpt.h>
#include <efilib.h>

#include "util.h"
#include "xbootldr.h"

union GptHeaderBuffer {
        EFI_PARTITION_TABLE_HEADER gpt_header;
        uint8_t space[CONST_ALIGN_TO(sizeof(EFI_PARTITION_TABLE_HEADER), 512)];
};

static EFI_DEVICE_PATH *path_chop(EFI_DEVICE_PATH *path, EFI_DEVICE_PATH *node) {
        assert(path);
        assert(node);

        UINTN len = (UINT8 *) node - (UINT8 *) path;
        EFI_DEVICE_PATH *chopped = xallocate_pool(len + END_DEVICE_PATH_LENGTH);

        CopyMem(chopped, path, len);
        SetDevicePathEndNode((EFI_DEVICE_PATH *) ((UINT8 *) chopped + len));

        return chopped;
}

static BOOLEAN verify_gpt(union GptHeaderBuffer *gpt_header_buffer, EFI_LBA lba_expected) {
        EFI_PARTITION_TABLE_HEADER *h;
        UINT32 crc32, crc32_saved;
        EFI_STATUS err;

        assert(gpt_header_buffer);

        h = &gpt_header_buffer->gpt_header;

        /* Some superficial validation of the GPT header */
        if (CompareMem(&h->Header.Signature, "EFI PART", sizeof(h->Header.Signature)) != 0)
                return FALSE;

        if (h->Header.HeaderSize < 92 || h->Header.HeaderSize > 512)
                return FALSE;

        if (h->Header.Revision != 0x00010000U)
                return FALSE;

        /* Calculate CRC check */
        crc32_saved = h->Header.CRC32;
        h->Header.CRC32 = 0;
        err = BS->CalculateCrc32(gpt_header_buffer, h->Header.HeaderSize, &crc32);
        h->Header.CRC32 = crc32_saved;
        if (EFI_ERROR(err) || crc32 != crc32_saved)
                return FALSE;

        if (h->MyLBA != lba_expected)
                return FALSE;

        if (h->SizeOfPartitionEntry < sizeof(EFI_PARTITION_ENTRY))
                return FALSE;

        if (h->NumberOfPartitionEntries <= 0 || h->NumberOfPartitionEntries > 1024)
                return FALSE;

        /* overflow check */
        if (h->SizeOfPartitionEntry > UINTN_MAX / h->NumberOfPartitionEntries)
                return FALSE;

        return TRUE;
}

static EFI_STATUS try_gpt(
                EFI_BLOCK_IO *block_io,
                EFI_LBA lba,
                EFI_LBA *ret_backup_lba, /* May be changed even on error! */
                HARDDRIVE_DEVICE_PATH *ret_hd) {

        _cleanup_freepool_ EFI_PARTITION_ENTRY *entries = NULL;
        union GptHeaderBuffer gpt;
        EFI_STATUS err;
        UINT32 crc32;
        UINTN size;

        assert(block_io);
        assert(ret_hd);

        /* Read the GPT header */
        err = block_io->ReadBlocks(
                        block_io,
                        block_io->Media->MediaId,
                        lba,
                        sizeof(gpt), &gpt);
        if (EFI_ERROR(err))
                return err;

        /* Indicate the location of backup LBA even if the rest of the header is corrupt. */
        if (ret_backup_lba)
                *ret_backup_lba = gpt.gpt_header.AlternateLBA;

        if (!verify_gpt(&gpt, lba))
                return EFI_NOT_FOUND;

        /* Now load the GPT entry table */
        size = ALIGN_TO((UINTN) gpt.gpt_header.SizeOfPartitionEntry * (UINTN) gpt.gpt_header.NumberOfPartitionEntries, 512);
        entries = xallocate_pool(size);

        err = block_io->ReadBlocks(
                        block_io,
                        block_io->Media->MediaId,
                        gpt.gpt_header.PartitionEntryLBA,
                        size, entries);
        if (EFI_ERROR(err))
                return err;

        /* Calculate CRC of entries array, too */
        err = BS->CalculateCrc32(entries, size, &crc32);
        if (EFI_ERROR(err) || crc32 != gpt.gpt_header.PartitionEntryArrayCRC32)
                return EFI_CRC_ERROR;

        /* Now we can finally look for xbootloader partitions. */
        for (UINTN i = 0; i < gpt.gpt_header.NumberOfPartitionEntries; i++) {
                EFI_PARTITION_ENTRY *entry;
                EFI_LBA start, end;

                entry = (EFI_PARTITION_ENTRY*) ((UINT8*) entries + gpt.gpt_header.SizeOfPartitionEntry * i);

                if (CompareMem(&entry->PartitionTypeGUID, XBOOTLDR_GUID, sizeof(entry->PartitionTypeGUID)) != 0)
                        continue;

                /* Let's use memcpy(), in case the structs are not aligned (they really should be though) */
                CopyMem(&start, &entry->StartingLBA, sizeof(start));
                CopyMem(&end, &entry->EndingLBA, sizeof(end));

                if (end < start) /* Bogus? */
                        continue;

                ret_hd->PartitionNumber = i + 1;
                ret_hd->PartitionStart = start;
                ret_hd->PartitionSize = end - start + 1;
                ret_hd->MBRType = MBR_TYPE_EFI_PARTITION_TABLE_HEADER;
                ret_hd->SignatureType = SIGNATURE_TYPE_GUID;
                CopyMem(ret_hd->Signature, &entry->UniquePartitionGUID, sizeof(ret_hd->Signature));

                return EFI_SUCCESS;
        }

        /* This GPT was fully valid, but we didn't find what we are looking for. This
         * means there's no reason to check the second copy of the GPT header */
        return EFI_NOT_FOUND;
}

static EFI_STATUS find_device(EFI_HANDLE *device, EFI_DEVICE_PATH **ret_device_path) {
        EFI_STATUS err;

        assert(device);
        assert(ret_device_path);

        EFI_DEVICE_PATH *partition_path = DevicePathFromHandle(device);
        if (!partition_path)
                return EFI_NOT_FOUND;

        /* Find the (last) partition node itself. */
        EFI_DEVICE_PATH *part_node = NULL;
        for (EFI_DEVICE_PATH *node = partition_path; !IsDevicePathEnd(node); node = NextDevicePathNode(node)) {
                if (DevicePathType(node) != MEDIA_DEVICE_PATH)
                        continue;

                if (DevicePathSubType(node) != MEDIA_HARDDRIVE_DP)
                        continue;

                part_node = node;
        }

        if (!part_node)
                return EFI_NOT_FOUND;

        /* Chop off the partition part, leaving us with the full path to the disk itself. */
        _cleanup_freepool_ EFI_DEVICE_PATH *disk_path = NULL;
        EFI_DEVICE_PATH *p = disk_path = path_chop(partition_path, part_node);

        EFI_HANDLE disk_handle;
        EFI_BLOCK_IO *block_io;
        err = BS->LocateDevicePath(&BlockIoProtocol, &p, &disk_handle);
        if (EFI_ERROR(err))
                return err;

        err = BS->HandleProtocol(disk_handle, &BlockIoProtocol, (void **)&block_io);
        if (EFI_ERROR(err))
                return err;

        /* Filter out some block devices early. (We only care about block devices that aren't
         * partitions themselves — we look for GPT partition tables to parse after all —, and only
         * those which contain a medium and have at least 2 blocks.) */
        if (block_io->Media->LogicalPartition ||
            !block_io->Media->MediaPresent ||
            block_io->Media->LastBlock <= 1)
                return EFI_NOT_FOUND;

        /* Try several copies of the GPT header, in case one is corrupted */
        EFI_LBA backup_lba = 0;
        HARDDRIVE_DEVICE_PATH hd = *((HARDDRIVE_DEVICE_PATH *) part_node);
        for (UINTN nr = 0; nr < 3; nr++) {
                EFI_LBA lba;

                /* Read the first copy at LBA 1 and then try the backup GPT header pointed
                 * to by the first header if that one was corrupted. As a last resort,
                 * try the very last LBA of this block device. */
                if (nr == 0)
                        lba = 1;
                else if (nr == 1 && backup_lba != 0)
                        lba = backup_lba;
                else if (nr == 2 && backup_lba != block_io->Media->LastBlock)
                        lba = block_io->Media->LastBlock;
                else
                        continue;

                err = try_gpt(
                        block_io, lba,
                        nr == 0 ? &backup_lba : NULL, /* Only get backup LBA location from first GPT header. */
                        &hd);
                if (EFI_ERROR(err)) {
                        /* GPT was valid but no XBOOT loader partition found. */
                        if (err == EFI_NOT_FOUND)
                                break;
                        /* Bad GPT, try next one. */
                        continue;
                }

                /* Patch in the data we found */
                EFI_DEVICE_PATH *xboot_path = ASSERT_SE_PTR(DuplicateDevicePath(partition_path));
                CopyMem((UINT8 *) xboot_path + ((UINT8 *) part_node - (UINT8 *) partition_path), &hd, sizeof(hd));
                *ret_device_path = xboot_path;
                return EFI_SUCCESS;
        }

        /* No xbootloader partition found */
        return EFI_NOT_FOUND;
}

EFI_STATUS xbootldr_open(EFI_HANDLE *device, EFI_HANDLE *ret_device, EFI_FILE **ret_root_dir) {
        _cleanup_freepool_ EFI_DEVICE_PATH *partition_path = NULL;
        EFI_HANDLE new_device;
        EFI_FILE *root_dir;
        EFI_STATUS err;

        assert(device);
        assert(ret_device);
        assert(ret_root_dir);

        err = find_device(device, &partition_path);
        if (EFI_ERROR(err))
                return err;

        EFI_DEVICE_PATH *dp = partition_path;
        err = BS->LocateDevicePath(&BlockIoProtocol, &dp, &new_device);
        if (EFI_ERROR(err))
                return err;

        root_dir = LibOpenRoot(new_device);
        if (!root_dir)
                return EFI_NOT_FOUND;

        *ret_device = new_device;
        *ret_root_dir = root_dir;
        return EFI_SUCCESS;
}
