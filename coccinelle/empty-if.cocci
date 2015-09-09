@@
expression e, f, g, h, i, j;
statement s, t;
@@
(
if (e) {
(
if (h) s
|
if (h) s else t
|
while (h) s
|
for (h; i; j) s
)
}
|
while (e) {
(
if (h) s
|
if (h) s else t
|
while (h) s
|
for (h; i; j) s
)
}
|
for (e; f; g) {
(
if (h) s
|
if (h) s else t
|
while (h) s
|
for (h; i; j) s
)
}
|
- if (e) {
+ if (e)
s
- }
|
- while (e) {
+ while (e)
s
- }
|
- for (e; f; g) {
+ for (e; f; g)
s
- }
)
