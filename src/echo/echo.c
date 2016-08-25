/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2013 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/


#include <stdio.h>
#include <stdlib.h>

static void
usage(void)
{
	puts("usage: echo [whatever...]");
	exit(1);
}

int
main(int argc, char *argv[])
{
	unsigned short int i;
	if(argc <= 1)
		usage();

	for(i = 1; i < argc; i++){
		printf("%s", argv[i]);
		printf(" ");
	}
	printf("\n");

	return (0);
}
