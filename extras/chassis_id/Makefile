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
CFLAGS = -g 
TARGET = chassis_id

all:	chassis_id  

chassis_id:	chassis_id.c table.c
	gcc -o $(TARGET) $(CFLAGS) chassis_id.c table.c

clean:	
	rm -rf core a.out $(TARGET)
