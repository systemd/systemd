@@
expression s;
@@
- memset(&s, 0, sizeof(s))
+ zero(s)
@@
expression s;
@@
- memset(s, 0, sizeof(*s))
+ zero(*s)
@@
expression s;
@@
- bzero(&s, sizeof(s))
+ zero(s)
@@
expression s;
@@
- bzero(s, sizeof(*s))
+ zero(*s)
@@
expression a, b;
@@
- memset(a, 0, b)
+ memzero(a, b)
@@
expression a, b;
@@
- bzero(a, b)
+ memzero(a, b)
