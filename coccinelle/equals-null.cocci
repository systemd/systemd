@@
expression e;
statement s;
@@
if (
(
!e
|
- e == NULL
+ !e
)
   )
   {...}
else s

@@
expression e;
statement s;
@@
if (
(
e
|
- e != NULL
+ e
)
   )
   {...}
else s
