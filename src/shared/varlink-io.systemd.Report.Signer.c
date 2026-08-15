/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Report.Signer.h"

static SD_VARLINK_DEFINE_METHOD(
                Sign,
                SD_VARLINK_FIELD_COMMENT("The digest of the data to sign."),
                SD_VARLINK_DEFINE_INPUT(digest, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The digest algorithm used for the digest field above. For now this is always SHA256, but this might be changed eventually."),
                SD_VARLINK_DEFINE_INPUT(algorithm, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("An array of signature objects"),
                SD_VARLINK_DEFINE_OUTPUT(data, SD_VARLINK_OBJECT, SD_VARLINK_ARRAY));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Report_Signer,
                "io.systemd.Report.Signer",
                SD_VARLINK_INTERFACE_COMMENT("Backend API for signing reports. This interface shall be implemented by services linked into /run/systemd/report.sign/."),
                SD_VARLINK_SYMBOL_COMMENT("Sign a report, identified by a digest. This may return zero, one or more signatures, as appropriate. For example some backend might have multiple keys or algorithms available, that are appropriate, in which case it can generate multiple signatures."),
                &vl_method_Sign);
