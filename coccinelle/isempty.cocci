/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
/* Disable this transformation for the test-string-util.c */
position p : script:python() { p[0].file != "src/test/test-string-util.c" };
expression s;
@@
(
- strv_length@p(s) == 0
+ strv_isempty(s)
|
- strv_length@p(s) <= 0
+ strv_isempty(s)
|
- strv_length@p(s) > 0
+ !strv_isempty(s)
|
- strv_length@p(s) != 0
+ !strv_isempty(s)
|
- strlen@p(s) == 0
+ isempty(s)
|
- strlen@p(s) <= 0
+ isempty(s)
|
- strlen@p(s) > 0
+ !isempty(s)
|
- strlen@p(s) != 0
+ !isempty(s)
|
- strlen_ptr@p(s) == 0
+ isempty(s)
|
- strlen_ptr@p(s) <= 0
+ isempty(s)
|
- strlen_ptr@p(s) > 0
+ !isempty(s)
|
- strlen_ptr@p(s) != 0
+ !isempty(s)
)
