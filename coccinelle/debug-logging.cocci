@@
@@
(
#define DEBUG_LOGGING
&
- _unlikely_(log_get_max_level() >= LOG_DEBUG)
+ DEBUG_LOGGING
)
@@
@@
(
#define DEBUG_LOGGING
&
- log_get_max_level() >= LOG_DEBUG
+ DEBUG_LOGGING
)
