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

#include "printclr.h"

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#define FG_RESET "\x1b[0m" 

static const char *s_ansi_fg_table[] = {
    [FG_BLACK]   = "\x1b[30m",
    [FG_RED]     = "\x1b[31m",
    [FG_GREEN]   = "\x1b[32m",
    [FG_YELLOW]  = "\x1b[33m",
    [FG_BLUE]    = "\x1b[34m",
    [FG_MAGENTA] = "\x1b[35m",
    [FG_CYAN]    = "\x1b[36m",
    [FG_WHITE]   = "\x1b[37m"
};

void printclr(fg_clr_t fg, const char *fmt, ...)
{
    va_list args;

    assert(fg > 0 && fg <= sizeof(s_ansi_fg_table)/sizeof(char*));
    printf("%s", s_ansi_fg_table[fg]);	

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    printf(FG_RESET);
}

