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

static void           search_handle_func(bf_htorrent_t *torrent, void *arg);
static bf_htorrent_t *handle_at_index(int index);
static int            num_torrents(void);
static void           print_usage(const char *cmdname);
static void           ls_cmd_foreach_func(bf_htorrent_t *torrent, void *arg);

struct search_arg {
    int target;
    int curr;
    bf_htorrent_t *out;
};

static void search_handle_func(bf_htorrent_t *torrent, void *arg)
{
    struct search_arg *sarg = (struct search_arg*)arg;    

    if(sarg->target == sarg->curr){
        sarg->out = torrent;        
    }
    
    sarg->curr++;
}

static bf_htorrent_t *handle_at_index(int index)
{
    struct search_arg arg;
    arg.target = index;
    arg.curr = 0;
    arg.out = NULL;

    bitfiend_foreach_torrent(search_handle_func, &arg);

    return arg.out;
}

static int num_torrents(void)
{
    struct search_arg arg;
    arg.target = -1;
    arg.curr = 0;

    bitfiend_foreach_torrent(search_handle_func, &arg);

    return arg.curr;
}

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

static int exit_cmd(int argc, char **argv)
{
    if(num_torrents() > 0) {
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
    int *index = (int*)arg;

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

    int index = 0;
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

static int rm_cmd(int argc, char **argv)
{
    if(argc != 2){
        print_usage(argv[0]);
        return CMD_FAIL_CMD;
    }

    char *end;
    int index = strtoul(argv[1], &end, 0);
    if(argv[1] == end){
        printf("Could not parse %s as an index.\n", argv[1]);
        return CMD_FAIL_CMD;
    }

    bf_htorrent_t *handle = handle_at_index(index);

    if(handle){
        printf("Announcing to torrent tracker and closing ongoing connections. "
               "This may take a few seconds...\n");

        bitfiend_remove_torrent(handle);

        printf("Successfully removed torrent at index %d.\n", index);
    }else{
        printf("Could not remove torrent at index: %d.\n", index);
    }

    return CMD_SUCCESS;
}

static int stat_cmd(int argc, char **argv)
{
    if(argc != 2){
        print_usage(argv[0]);
        return CMD_FAIL_CMD;
    }

    int index;
    char *end;
    index = strtoul(argv[1], &end, 0);
    if(end == argv[1]){
        printf("Could not parse %s as an index.\n", argv[1]);
        return CMD_FAIL_CMD;   
    } 

    bf_htorrent_t *handle = handle_at_index(index);
    if(!handle){
        printf("Could not find torrent at index %d.\n", index);
        return CMD_FAIL_CMD;
    }

    bf_stat_t stat;
    bitfiend_stat_torrent(handle, &stat);
    float percent = (1.0f - ((float)stat.pieces_left)/stat.tot_pieces) * 100;

    printf("%-20s: %s\n", "Torrent", stat.name);
    printf("%-20s: %2.2f%%\n", "Completion", percent);
    printf("%-20s: %lu bytes\n", "Total Downloaded", stat.tot_downloaded);
    printf("%-20s: %lu bytes\n", "Total Uploaded", stat.tot_uploaded);
    printf("%-20s: %.2f bits/sec\n", "Avg. upload rate", stat.avg_uprate);
    printf("%-20s: %.2f bits/sec\n", "Avg. download rate", stat.avg_downrate);
    printf("%-20s: %.2f bits/sec\n", "Inst. upload rate", stat.inst_uprate);
    printf("%-20s: %.2f bits/sec\n", "Inst. download rate", stat.inst_downrate);

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

