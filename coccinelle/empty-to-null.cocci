@@
expression s;
@@
- isempty(s) ? NULL : s
+ empty_to_null(s)
