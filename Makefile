# SPDX-License-Identifier: LGPL-2.1-or-later

all:
	ninja -C build

install:
	DESTDIR=$(DESTDIR) ninja -C build install
