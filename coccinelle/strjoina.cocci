/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
position p : script:python() { p[0].current_element != "test_strjoina" };
expression n, m;
expression list s;
@@
- n = strjoina@p(m, s, NULL);
+ n = strjoina(m, s);
