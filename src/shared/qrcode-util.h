/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if HAVE_QRENCODE
#include <qrencode.h>
#include <stdio.h>

void write_qrcode(FILE *output, QRcode *qr);
#endif
