#
#   **
#   ** (C) 2003 Intel Corporation
#   **          Atul Sabharwal <atul.sabharwal@intel.com>
#   **
#   ** $Id: Makefile,v 1.3 2004/03/22 23:54:54 atul Exp $
#   **
#   ** Distributed under the terms of the GNU Public License, v2.0 or
#   ** later.
#   **
#   ** Many parts heavily based on test-skeleton.c, by Ulrich Drepper;
#   ** with his permission, they have been re-licensed GPL, and his
#   ** copyright still applies on them. 
#   **
#   */
#
CFLAGS = -g 
TARGET = chassis_id

all:	chassis_id  

chassis_id:	chassis_id.c table.c
	gcc -o $(TARGET) $(CFLAGS) chassis_id.c table.c

clean:	
	rm -rf core a.out $(TARGET)
