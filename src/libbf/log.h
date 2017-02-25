#ifndef LOG_H
#define LOG_H

#include <stdio.h>

typedef enum{
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_NONE
}log_level_t;

#define DEFAULT_LOG_LVL LOG_LEVEL_INFO

void log_set_lvl(log_level_t lvl);
void log_set_logfile(FILE *f);
void log_printf(log_level_t lvl, const char *fmt, ...);

#endif
