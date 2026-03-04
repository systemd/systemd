/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
/* Disable this transformation on test-json.c */
position p : script:python() { p[0].file != "src/test/test-json.c" };
expression key, val;
@@
(
- SD_JSON_BUILD_PAIR@p(key, SD_JSON_BUILD_BOOLEAN(val))
+ SD_JSON_BUILD_PAIR_BOOLEAN(key, val)
|
- SD_JSON_BUILD_PAIR@p(key, SD_JSON_BUILD_INTEGER(val))
+ SD_JSON_BUILD_PAIR_INTEGER(key, val)
|
- SD_JSON_BUILD_PAIR@p(key, SD_JSON_BUILD_STRING(val))
+ SD_JSON_BUILD_PAIR_STRING(key, val)
|
- SD_JSON_BUILD_PAIR@p(key, SD_JSON_BUILD_UNSIGNED(val))
+ SD_JSON_BUILD_PAIR_UNSIGNED(key, val)
|
- SD_JSON_BUILD_PAIR@p(key, SD_JSON_BUILD_VARIANT(val))
+ SD_JSON_BUILD_PAIR_VARIANT(key, val)
)
