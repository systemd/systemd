/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "timesyncd-ntp-extension.h"
#include "timesyncd-manager.h"

int nts_build_request_packet(NTSKEPacket **ret);
int ntp_extension_build_request_packet(Manager *m, struct ntp_msg *ntpmsg, size_t *size);
int ntp_extension_encrypt_auth_field(Manager *m, struct ntp_msg *ntpmsg, NTPExtensionPacket *packet);
int ntp_extension_parse_extention_field(Manager *m, struct ntp_msg *ntpmsg, size_t size);
