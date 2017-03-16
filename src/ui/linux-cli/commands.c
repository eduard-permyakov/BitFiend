#include "commands.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define ARR_SIZE(a) (sizeof(a)/sizeof((a)[0]))

typedef struct cmd {
	const char *name;
	int (*func)(int argc, char **argv);
}cmd_t;

static int exit_cmd(int argc, char **argv);
static int help_cmd(int argc, char **argv);
static int ls_cmd(int argc, char **argv);
static int add_cmd(int argc, char **argv);
static int rm_cmd(int argc, char **argv);
static int stat_cmd(int argc, char **argv);

static cmd_t s_cmd_table[] = {
	{"exit", exit_cmd},
	{"help", help_cmd},
	{"ls", 	 ls_cmd	 },	
	{"add",  add_cmd },
	{"rm", 	 rm_cmd, },
	{"stat", stat_cmd}
};

int command_exec(int argc, char **argv)
{

}

int command_parse_and_exec(char *str)
{
	int (*func)(int argc, char **argv) = NULL;
	const char *delims = " \t\n";
	char *token;
	int argc = 0;

	char copy[strlen(str) + 1];
	strcpy(copy, str);
	token = strtok(copy, delims);
	while(token) {
	    argc++;
		token = strtok(NULL, delims);
	}

	if(argc == 0)
		return CMD_FAIL_EXEC;

	token = strtok(str, delims);
	for(int i = 0; i < ARR_SIZE(s_cmd_table); i++){
		if(!strcmp(token, s_cmd_table[i].name)) {
			func = s_cmd_table[i].func;	
			break;
		}
	}

	if(!func)
		return CMD_FAIL_EXEC;

	char *argv[argc];
	int i = 0;
	do {
		assert(i < argc);
		argv[i++] = token;
		token = strtok(NULL, delims);
	}while(token);
	assert(i == argc);

	return func(argc, argv);
}

static int exit_cmd(int argc, char **argv)
{
	printf("Exiting...\n");
	exit(EXIT_SUCCESS);
}

static int help_cmd(int argc, char **argv)
{
	printf("help\n");
	return CMD_SUCCESS;
}

static int ls_cmd(int argc, char **argv)
{
	return CMD_SUCCESS;
}

static int add_cmd(int argc, char **argv)
{
	return CMD_SUCCESS;
}

static int rm_cmd(int argc, char **argv)
{
	return CMD_SUCCESS;
}

static int stat_cmd(int argc, char **argv)
{
	return CMD_SUCCESS;
}

