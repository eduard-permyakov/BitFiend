#ifndef PRINTCLR
#define PRINTCLR

typedef enum {
	FG_BLACK = 0,
	FG_RED,
	FG_GREEN,
	FG_YELLOW,
	FG_BLUE,
	FG_MAGENTA,
	FG_CYAN,
	FG_WHITE
}fg_clr_t;

void printclr(fg_clr_t fg, const char *fmt, ...);

#endif
