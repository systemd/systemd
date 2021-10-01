/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
position p : script:python() { p[0].current_element != "test_strjoin" };
expression t;
expression list args;
@@
(
- strjoin@p(args, NULL);
+ strjoin(args);
|
- t = strjoin@p(args, NULL);
+ t = strjoin(args);
|
- return strjoin@p(args, NULL);
+ return strjoin(args);
)
