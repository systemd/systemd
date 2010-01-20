/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foologhfoo
#define foologhfoo

#include <syslog.h>

#include "macro.h"

void log_meta(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format, ...) __printf_attr(5,6);

#define log_debug(...)   log_meta(LOG_DEBUG,   __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_info(...)    log_meta(LOG_INFO,    __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_notice(...)  log_meta(LOG_NOTICE,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_warning(...) log_meta(LOG_WARNING, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_error(...)   log_meta(LOG_ERR,     __FILE__, __LINE__, __func__, __VA_ARGS__)

#endif
