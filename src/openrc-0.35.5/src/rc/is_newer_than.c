/*
 * Copyright (c) 2016 The OpenRC Authors.
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
#include <stdio.h>
#include <stdlib.h>

#include "rc.h"
#include "rc-misc.h"

int main(int argc, char **argv)
{
	int i;

	if (argc < 3)
		return EXIT_FAILURE;

	/* This test is correct as it's not present in baselayout */
	for (i = 2; i < argc; ++i)
		if (!rc_newer_than(argv[1], argv[i], NULL, NULL))
			return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
