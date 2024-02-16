/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression p, s;
@@
- siphash24_compress(&p, sizeof(p), s);
+ siphash24_compress_typesafe(p, s);

@@
union in_addr_union p;
expression f, s;
@@
- siphash24_compress(&p, FAMILY_ADDRESS_SIZE(f), s);
+ in_addr_hash_func(&p, f, s);
