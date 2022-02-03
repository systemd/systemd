/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression s;
@@
- htonl(s)
+ htobe32(s)
@@
expression s;
@@
- htons(s)
+ htobe16(s)
@@
expression s;
@@
- ntohl(s)
+ be32toh(s)
@@
expression s;
@@
- ntohs(s)
+ be16toh(s)
