/*    
 *  This file is part of BitFiend. 
 *  Copyright (C) 2017 Eduard Permyakov 
 *
 *  BitFiend is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  BitFiend is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "log.h"

#include <pthread.h>
#include <stdarg.h>
#include <time.h>

#include <unistd.h>
#include <sys/syscall.h>

static pthread_mutex_t  s_log_lock = PTHREAD_MUTEX_INITIALIZER;
static int              s_loglevel = DEFAULT_LOG_LVL;
static FILE            *s_logfile = NULL;

void log_set_lvl(log_level_t lvl)
{
    pthread_mutex_lock(&s_log_lock);
    s_loglevel = lvl;
    pthread_mutex_unlock(&s_log_lock);
}

void log_set_logfile(FILE *f)
{
    pthread_mutex_lock(&s_log_lock);
    s_logfile = f;
    pthread_mutex_unlock(&s_log_lock);
}

void log_printf(log_level_t lvl, const char *fmt, ...)
{
    va_list args;
    long tid = (long)syscall(SYS_gettid);
    time_t now = time(0);
    char timestr[9];

    strftime(timestr, sizeof(timestr), "%H:%M:%S", localtime(&now));

    pthread_mutex_lock(&s_log_lock);

    if(lvl < s_loglevel){
        pthread_mutex_unlock(&s_log_lock);
        return;
    }

    fprintf(s_logfile, "[%.*s] [%05ld] ", 8, timestr, tid);  
    switch(lvl){
        case LOG_LEVEL_WARNING:
            fprintf(s_logfile, "WARNING: ");
            break;
        case LOG_LEVEL_ERROR:
            fprintf(s_logfile, "ERROR: ");
            break;
    }

    va_start(args, fmt);
    vfprintf(s_logfile, fmt, args);
    va_end(args);

    pthread_mutex_unlock(&s_log_lock);

    fflush(s_logfile);
}

