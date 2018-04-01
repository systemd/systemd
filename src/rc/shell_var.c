/*
 * Copyright (c) 2007-2015 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */

#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int i;
	char *p;
	int c;

	for (i = 1; i < argc; i++) {
		p = argv[i];
		if (i != 1)
			putchar(' ');
		while (*p) {
			c = (unsigned char)*p++;
			if (! isalnum(c))
				c = '_';
			putchar(c);
		}
	}
	putchar('\n');
	return EXIT_SUCCESS;
}
