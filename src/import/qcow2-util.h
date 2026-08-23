/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int qcow2_detect(int fd);
int qcow2_convert(int qcow2_fd, int raw_fd);
