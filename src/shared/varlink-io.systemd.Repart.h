/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink-idl.h"

extern const sd_varlink_interface vl_interface_io_systemd_Repart;
extern const sd_varlink_symbol vl_type_BlockDeviceAction;

extern const sd_varlink_symbol vl_error_NoCandidateDevices;
extern const sd_varlink_symbol vl_error_ConflictingDiskLabelPresent;
extern const sd_varlink_symbol vl_error_InsufficientFreeSpace;
extern const sd_varlink_symbol vl_error_DiskTooSmall;
