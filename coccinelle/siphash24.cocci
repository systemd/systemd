/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression p, s;
@@
- siphash24_compress(&p, sizeof(p), s);
+ siphash24_compress_typesafe(p, s);
