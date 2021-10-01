/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
position p : script:python() { not p[0].file.startswith("man/") };
expression e, fmt;
expression list vaargs;
@@
- snprintf@p(e, sizeof(e), fmt, vaargs);
+ xsprintf(e, fmt, vaargs);
