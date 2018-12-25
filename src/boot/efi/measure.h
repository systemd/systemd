/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

EFI_STATUS tpm_log_event(UINT32 pcrindex,
                         const EFI_PHYSICAL_ADDRESS buffer,
                         UINTN buffer_size,
                         const CHAR16 *description);
