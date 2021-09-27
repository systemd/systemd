/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efigpt.h>
#include <efilib.h>

#include "util.h"
#include "xbootldr.h"

static EFI_DEVICE_PATH *path_parent(EFI_DEVICE_PATH *path, EFI_DEVICE_PATH *node) {
        EFI_DEVICE_PATH *parent;
        UINTN len;

        assert(path);
        assert(node);

        len = (UINT8*) NextDevicePathNode(node) - (UINT8*) path;
        parent = (EFI_DEVICE_PATH*) AllocatePool(len + sizeof(EFI_DEVICE_PATH));
        CopyMem(parent, path, len);
        CopyMem((UINT8*) parent + len, EndDevicePath, sizeof(EFI_DEVICE_PATH));

        return parent;
}

EFI_STATUS xbootldr_open(EFI_HANDLE *device, EFI_HANDLE *ret_device, EFI_FILE **ret_root_dir) {
        EFI_DEVICE_PATH *partition_path, *disk_path, *copy;
        UINT32 found_partition_number = UINT32_MAX;
        UINT64 found_partition_start = UINT64_MAX;
        UINT64 found_partition_size = UINT64_MAX;
        UINT8 found_partition_signature[16] = {};
        EFI_HANDLE new_device;
        EFI_FILE *root_dir;
        EFI_STATUS r;

        assert(device);
        assert(ret_device);
        assert(ret_root_dir);

        partition_path = DevicePathFromHandle(device);
        if (!partition_path)
                return EFI_NOT_FOUND;

        for (EFI_DEVICE_PATH *node = partition_path; !IsDevicePathEnd(node); node = NextDevicePathNode(node)) {
                EFI_HANDLE disk_handle;
                EFI_BLOCK_IO *block_io;
                EFI_DEVICE_PATH *p;

                /* First, Let's look for the SCSI/SATA/USB/… device path node, i.e. one above the media
                 * devices */
                if (DevicePathType(node) != MESSAGING_DEVICE_PATH)
                        continue;

                /* Determine the device path one level up */
                disk_path = path_parent(partition_path, node);
                p = disk_path;
                r = uefi_call_wrapper(BS->LocateDevicePath, 3, &BlockIoProtocol, &p, &disk_handle);
                if (EFI_ERROR(r))
                        continue;

                r = uefi_call_wrapper(BS->HandleProtocol, 3, disk_handle, &BlockIoProtocol, (VOID **)&block_io);
                if (EFI_ERROR(r))
                        continue;

                /* Filter out some block devices early. (We only care about block devices that aren't
                 * partitions themselves — we look for GPT partition tables to parse after all —, and only
                 * those which contain a medium and have at least 2 blocks.) */
                if (block_io->Media->LogicalPartition ||
                    !block_io->Media->MediaPresent ||
                    block_io->Media->LastBlock <= 1)
                        continue;

                /* Try both copies of the GPT header, in case one is corrupted */
                for (UINTN nr = 0; nr < 2; nr++) {
                        _cleanup_freepool_ EFI_PARTITION_ENTRY* entries = NULL;
                        union {
                                EFI_PARTITION_TABLE_HEADER gpt_header;
                                uint8_t space[((sizeof(EFI_PARTITION_TABLE_HEADER) + 511) / 512) * 512];
                        } gpt_header_buffer;
                        EFI_PARTITION_TABLE_HEADER *h = &gpt_header_buffer.gpt_header;
                        UINT64 where;
                        UINTN sz;
                        UINT32 crc32, crc32_saved;

                        if (nr == 0)
                                /* Read the first copy at LBA 1 */
                                where = 1;
                        else
                                /* Read the second copy at the very last LBA of this block device */
                                where = block_io->Media->LastBlock;

                        /* Read the GPT header */
                        r = uefi_call_wrapper(block_io->ReadBlocks, 5,
                                              block_io,
                                              block_io->Media->MediaId,
                                              where,
                                              sizeof(gpt_header_buffer), &gpt_header_buffer);
                        if (EFI_ERROR(r))
                                continue;

                        /* Some superficial validation of the GPT header */
                        if(CompareMem(&h->Header.Signature, "EFI PART", sizeof(h->Header.Signature) != 0))
                                continue;

                        if (h->Header.HeaderSize < 92 ||
                            h->Header.HeaderSize > 512)
                                continue;

                        if (h->Header.Revision != 0x00010000U)
                                continue;

                        /* Calculate CRC check */
                        crc32_saved = h->Header.CRC32;
                        h->Header.CRC32 = 0;
                        r = BS->CalculateCrc32(&gpt_header_buffer, h->Header.HeaderSize, &crc32);
                        h->Header.CRC32 = crc32_saved;
                        if (EFI_ERROR(r) || crc32 != crc32_saved)
                                continue;

                        if (h->MyLBA != where)
                                continue;

                        if (h->SizeOfPartitionEntry < sizeof(EFI_PARTITION_ENTRY))
                                continue;

                        if (h->NumberOfPartitionEntries <= 0 ||
                            h->NumberOfPartitionEntries > 1024)
                                continue;

                        if (h->SizeOfPartitionEntry > UINTN_MAX / h->NumberOfPartitionEntries) /* overflow check */
                                continue;

                        /* Now load the GPT entry table */
                        sz = ALIGN_TO((UINTN) h->SizeOfPartitionEntry * (UINTN) h->NumberOfPartitionEntries, 512);
                        entries = AllocatePool(sz);

                        r = uefi_call_wrapper(block_io->ReadBlocks, 5,
                                              block_io,
                                              block_io->Media->MediaId,
                                              h->PartitionEntryLBA,
                                              sz, entries);
                        if (EFI_ERROR(r))
                                continue;

                        /* Calculate CRC of entries array, too */
                        r = BS->CalculateCrc32(&entries, sz, &crc32);
                        if (EFI_ERROR(r) || crc32 != h->PartitionEntryArrayCRC32)
                                continue;

                        for (UINTN i = 0; i < h->NumberOfPartitionEntries; i++) {
                                EFI_PARTITION_ENTRY *entry;

                                entry = (EFI_PARTITION_ENTRY*) ((UINT8*) entries + h->SizeOfPartitionEntry * i);

                                if (CompareMem(&entry->PartitionTypeGUID, XBOOTLDR_GUID, 16) == 0) {
                                        UINT64 end;

                                        /* Let's use memcpy(), in case the structs are not aligned (they really should be though) */
                                        CopyMem(&found_partition_start, &entry->StartingLBA, sizeof(found_partition_start));
                                        CopyMem(&end, &entry->EndingLBA, sizeof(end));

                                        if (end < found_partition_start) /* Bogus? */
                                                continue;

                                        found_partition_size = end - found_partition_start + 1;
                                        CopyMem(found_partition_signature, &entry->UniquePartitionGUID, sizeof(found_partition_signature));

                                        found_partition_number = i + 1;
                                        goto found;
                                }
                        }

                        break; /* This GPT was fully valid, but we didn't find what we are looking for. This
                                * means there's no reason to check the second copy of the GPT header */
                }
        }

        return EFI_NOT_FOUND;

found:
        copy = DuplicateDevicePath(partition_path);

        /* Patch in the data we found */
        for (EFI_DEVICE_PATH *node = copy; !IsDevicePathEnd(node); node = NextDevicePathNode(node)) {
                HARDDRIVE_DEVICE_PATH *hd;

                if (DevicePathType(node) != MEDIA_DEVICE_PATH)
                        continue;

                if (DevicePathSubType(node) != MEDIA_HARDDRIVE_DP)
                        continue;

                hd = (HARDDRIVE_DEVICE_PATH*) node;
                hd->PartitionNumber = found_partition_number;
                hd->PartitionStart = found_partition_start;
                hd->PartitionSize = found_partition_size;
                CopyMem(hd->Signature, found_partition_signature, sizeof(hd->Signature));
                hd->MBRType = MBR_TYPE_EFI_PARTITION_TABLE_HEADER;
                hd->SignatureType = SIGNATURE_TYPE_GUID;
        }

        r = uefi_call_wrapper(BS->LocateDevicePath, 3, &BlockIoProtocol, &copy, &new_device);
        if (EFI_ERROR(r))
                return r;

        root_dir = LibOpenRoot(new_device);
        if (!root_dir)
                return EFI_DEVICE_ERROR;

        *ret_device = new_device;
        *ret_root_dir = root_dir;
        return EFI_SUCCESS;
}
