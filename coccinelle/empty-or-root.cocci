@@
expression s;
@@
- (isempty(s) || path_equal(s, "/"))
+ empty_or_root(s)
@@
expression s;
@@
- (!isempty(s) && !path_equal(s, "/"))
+ !empty_or_root(s)
