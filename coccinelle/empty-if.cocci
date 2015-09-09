@@
expression e, f;
statement s, t;
@@
(
if (e) {
if (f) s
}
|
if (e) {
if (f) s
else t
}
|
- if (e) {
+ if (e)
s
- }
)
