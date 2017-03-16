#ifndef COMMANDS_H
#define COMMANDS_H

#include <stddef.h>

enum {
	CMD_SUCCESS = 0,
	CMD_FAIL_EXEC,
	CMD_FAIL_CMD
};

int command_exec(int argc, char **argv);
int command_parse_and_exec(char *str);

#endif
