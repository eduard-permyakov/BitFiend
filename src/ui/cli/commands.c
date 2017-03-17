#include "commands.h"

#include <libbf/bitfiend.h>

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define ARR_SIZE(a) (sizeof(a)/sizeof((a)[0]))

typedef struct cmd {
	const char *name;
	int (*func)(int argc, char **argv);
    char *usage;
    char *desc;
}cmd_t;

static int exit_cmd(int argc, char **argv);
static int help_cmd(int argc, char **argv);
static int ls_cmd(int argc, char **argv);
static int add_cmd(int argc, char **argv);
static int rm_cmd(int argc, char **argv);
static int stat_cmd(int argc, char **argv);

static cmd_t s_cmd_table[] = {
	{"exit", exit_cmd, "exit"},
	{"help", help_cmd, "help"},
	{"ls", 	 ls_cmd,   "ls"},	
	{"add",  add_cmd,  "add <metadata_file> <output_dir>"},
	{"rm", 	 rm_cmd,   "rm <torrent index>"},
	{"stat", stat_cmd, "stat <torrent_index>"}
};

static void print_usage(const char *cmdname);
static void exit_cmd_foreach_func(bf_htorrent_t *torrent, void *arg);
static void ls_cmd_foreach_func(bf_htorrent_t *torrent, void *arg);
static void rm_cmd_foreach_func(bf_htorrent_t *torrent, void *arg);
static void stat_cmd_foreach_func(bf_htorrent_t *torrent, void *arg);


static void print_usage(const char *cmdname)
{
    for(int i = 0; i < ARR_SIZE(s_cmd_table); i++) {
        if(!strcmp(cmdname, s_cmd_table[i].name)){
            printf("Command usage: ");
            printf("%s\n", s_cmd_table[i].usage);
            break;
        }
    }
}

static void exit_cmd_foreach_func(bf_htorrent_t *torrent, void *arg)
{
    unsigned *num = (unsigned*)arg;
    (*num)++;
}

static int exit_cmd(int argc, char **argv)
{
    unsigned num = 0; 
    bitfiend_foreach_torrent(exit_cmd_foreach_func, &num);
    if(num > 0){
	    printf("Announcing to torrent tracker and closing ongoing connections. "
               "This may take a few seconds...\n");
    }
    bitfiend_shutdown();
	exit(EXIT_SUCCESS);
}

static int help_cmd(int argc, char **argv)
{
    if(argc != 1){
        print_usage(argv[0]);
        return CMD_FAIL_CMD;
    }

    for(int i = 0; i < ARR_SIZE(s_cmd_table); i++) {
        printf("    %s\n", s_cmd_table[i].usage);
    }

	return CMD_SUCCESS;
}

static void ls_cmd_foreach_func(bf_htorrent_t *torrent, void *arg)
{
    unsigned *index = (unsigned*)arg;

    bf_stat_t stat;
    bitfiend_stat_torrent(torrent, &stat);
    float percent = (1.0f - ((float)stat.pieces_left)/stat.tot_pieces) * 100;
    printf("%3u: %-60s %3.2f%%\n", *index, stat.name, percent);

    (*index)++;
}

static int ls_cmd(int argc, char **argv)
{
    if(argc != 1){
        print_usage(argv[0]);
        return CMD_FAIL_CMD;
    }

    unsigned index = 0;
    bitfiend_foreach_torrent(ls_cmd_foreach_func, &index);

	return CMD_SUCCESS;
}

static int add_cmd(int argc, char **argv)
{
    int ret;

    if(argc != 3){
        print_usage(argv[0]);
        return CMD_FAIL_CMD;
    }

    ret =  bitfiend_add_torrent(argv[1], argv[2]) ? CMD_SUCCESS : CMD_FAIL_CMD;
    if(ret == BITFIEND_SUCCESS)
        printf("Successfully added torrent.\n");
    else
        printf("Could not add torrent.\n");

    return ret;
}

struct rm_cmd_arg {
    unsigned target;
    unsigned curr;
    bool removed;
};

static void rm_cmd_foreach_func(bf_htorrent_t *torrent, void *arg)
{
    struct rm_cmd_arg *rarg = (struct rm_cmd_arg*)arg;

    if(rarg->curr == rarg->target){
	    printf("Announcing to torrent tracker and closing ongoing connections. "
               "This may take a few seconds...\n");

        bitfiend_remove_torrent(torrent); 
        rarg->removed = true;
    }
    rarg->curr++;
}

static int rm_cmd(int argc, char **argv)
{
    if(argc != 2){
        print_usage(argv[0]);
        return CMD_FAIL_CMD;
    }
    struct rm_cmd_arg arg;
    char *end;
    arg.target = strtoul(argv[1], &end, 0);
    if(argv[1] == end){
        printf("Could not parse %s as an index.\n", argv[1]);
        return CMD_FAIL_CMD;
    }
    arg.curr = 0;
    arg.removed = false;

    bitfiend_foreach_torrent(rm_cmd_foreach_func, &arg);
    if(arg.removed)
        printf("Successfully removed torrent at index %u.\n", arg.target);
    else
        printf("Could not remove torrent at index: %u.\n", arg.target);

	return CMD_SUCCESS;
}

struct stat_cmd_arg {
    unsigned target;
    unsigned curr;
    bool found;
};

static void stat_cmd_foreach_func(bf_htorrent_t *torrent, void *arg)
{
    struct stat_cmd_arg *sarg = (struct stat_cmd_arg*)arg;
    if(sarg->found)
        return;

    if(sarg->curr == sarg->target) {
        bf_stat_t stat;
        bitfiend_stat_torrent(torrent, &stat);
        float percent = (1.0f - ((float)stat.pieces_left)/stat.tot_pieces) * 100;
        printf("%3u: %-60s %3.2f%%\n", sarg->curr, stat.name, percent);    

        sarg->found = true;
    }

    sarg->curr++;
}

static int stat_cmd(int argc, char **argv)
{
    if(argc != 2){
        print_usage(argv[0]);
        return CMD_FAIL_CMD;
    }

    struct stat_cmd_arg arg;
    char *end;

    arg.target = strtoul(argv[1], &end, 0);
    if(end == argv[1]){
        printf("Could not parse %s as an index.\n", argv[1]);
        return CMD_FAIL_CMD;   
    } 
    arg.curr = 0;
    arg.found = false;

    bitfiend_foreach_torrent(stat_cmd_foreach_func, &arg);

    if(!arg.found)
        printf("Could not find torrent at index %u.\n", arg.target);

	return CMD_SUCCESS;
}

int command_exec(int argc, char **argv)
{
    for(int i = 0; i < ARR_SIZE(s_cmd_table); i++) {
        if(!strcmp(argv[0], s_cmd_table[i].name)){
            return s_cmd_table[i].func(argc, argv);
        }
    }
    return CMD_FAIL_EXEC;
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

