# * 
# * Makefile
# *
# * Copyright (C) 2004 Intel Corporation.  All rights reserved.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public
# * License v2.0 as published by the Free Software Foundation; 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * General Public License for more details.
# *
# * You should have received a copy of the GNU General Public
# * License along with this program; if not, write to the
# * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# * Boston, MA 021110-1307, USA.
# *
# * Authors: Atul Sabharwal
# *          
# *

TARGET = chassis_id

exec_prefix =   ${prefix}
sbindir =       ${exec_prefix}/sbin
INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
all:	chassis_id

ifneq ($(strip $(USE_KLIBC)),true)
chassis_id:	chassis_id.c table.c
	$(QUIET) $(CC) -o $(TARGET) $(CFLAGS) chassis_id.c table.c

install: all
	$(INSTALL_PROGRAM) $(TARGET) $(DESTDIR)$(sbindir)/$(TARGET)
else
chassis_id:
	@echo
	@echo "!!! chassis_id is incompatible with klibc !!!"
	@echo
	@exit 0

install: all
endif

clean:
	rm -rf core a.out $(TARGET)

