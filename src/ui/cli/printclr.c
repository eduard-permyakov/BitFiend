#include "printclr.h"

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#define FG_RESET "\x1b[0m" 

static const char *s_ansi_fg_table[] = {
	[FG_BLACK] 	 = "\x1b[30m",
	[FG_RED] 	 = "\x1b[31m",
	[FG_GREEN] 	 = "\x1b[32m",
	[FG_YELLOW]  = "\x1b[33m",
	[FG_BLUE]	 = "\x1b[34m",
	[FG_MAGENTA] = "\x1b[35m",
	[FG_CYAN]	 = "\x1b[36m",
	[FG_WHITE] 	 = "\x1b[37m"
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

