@@
expression s;
@@
- if (empty_or_root(s))
-         s = "/";
+ s = empty_to_root(s);
@@
expression s;
@@
- (empty_or_root(s) ? "/" : s)
+ empty_to_root(s)
