@@
expression p;
@@
- strchr(p, 0)
+ (p + strlen(p))

@@
expression p;
@@
- strrchr(p, 0)
+ (p + strlen(p))

@@
expression p;
@@
- strchr(p, '\0')
+ (p + strlen(p))

@@
expression p;
@@
- strrchr(p, '\0')
+ (p + strlen(p))

@@
expression p;
@@
- strstr(p, "")
+ (p + strlen(p))

@@
expression p;
@@
- strrstr(p, "")
+ (p + strlen(p))
