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
@@
/* Disable this transformation for the hashmap.h, set.h, test-hashmap.c, test-hashmap-plain.c */
position p : script:python() {
                p[0].file != "src/basic/hashmap.h" and
                p[0].file != "src/basic/set.h" and
                p[0].file != "src/test/test-hashmap.c" and
                p[0].file != "src/test/test-hashmap-plain.c"
        };
expression s;
@@
(
- hashmap_size@p(s) == 0
+ hashmap_isempty(s)
|
- hashmap_size@p(s) <= 0
+ hashmap_isempty(s)
|
- hashmap_size@p(s) > 0
+ !hashmap_isempty(s)
|
- hashmap_size@p(s) != 0
+ !hashmap_isempty(s)
|
- ordered_hashmap_size@p(s) == 0
+ ordered_hashmap_isempty(s)
|
- ordered_hashmap_size@p(s) <= 0
+ ordered_hashmap_isempty(s)
|
- ordered_hashmap_size@p(s) > 0
+ !ordered_hashmap_isempty(s)
|
- ordered_hashmap_size@p(s) != 0
+ !ordered_hashmap_isempty(s)
|
- set_size@p(s) == 0
+ set_isempty(s)
|
- set_size@p(s) <= 0
+ set_isempty(s)
|
- set_size@p(s) > 0
+ !set_isempty(s)
|
- set_size@p(s) != 0
+ !set_isempty(s)
|
- ordered_set_size@p(s) == 0
+ ordered_set_isempty(s)
|
- ordered_set_size@p(s) <= 0
+ ordered_set_isempty(s)
|
- ordered_set_size@p(s) > 0
+ !ordered_set_isempty(s)
|
- ordered_set_size@p(s) != 0
+ !ordered_set_isempty(s)
)
@@
expression s;
@@
(
- fdset_size(s) == 0
+ fdset_isempty(s)
|
- fdset_size(s) <= 0
+ fdset_isempty(s)
|
- fdset_size(s) > 0
+ !fdset_isempty(s)
|
- fdset_size(s) != 0
+ !fdset_isempty(s)
)
@@
expression s;
@@
(
- prioq_size(s) == 0
+ prioq_isempty(s)
|
- prioq_size(s) <= 0
+ prioq_isempty(s)
|
- prioq_size(s) > 0
+ !prioq_isempty(s)
|
- prioq_size(s) != 0
+ !prioq_isempty(s)
)
@@
expression s;
@@
(
- table_get_rows(s) <= 1
+ table_isempty(s)
|
- table_get_rows(s) > 1
+ !table_isempty(s)
)
