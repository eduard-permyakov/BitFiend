#include <libbf/bitfiend.h>
#include "printclr.h"
#include "commands.h"

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define CLI_VER_MAJOR 0
#define CLI_VER_MINOR 1

static volatile sig_atomic_t running = true;

static void sigint_handler(int signum)
{
    running = false; 
}

static void print_welcome(void)
{
    printf("    ____  _ __  _______                __\n");
    printf("   / __ )(_) /_/ ____(_)__  ____  ____/ /\n");
    printf("  / __  / / __/ /_  / / _ \\/ __ \\/ __  / \n");
    printf(" / /_/ / / /_/ __/ / /  __/ / / / /_/ /  \n");
    printf("/_____/_/\\__/_/   /_/\\___/_/ /_/\\__,_/   ");
    printf("libbf %d.%d cli %d.%d\n\n", LIBBF_VER_MAJOR, LIBBF_VER_MINOR, CLI_VER_MAJOR, CLI_VER_MINOR);
    printf("Copyright (c) 2017 Eduard Permyakov\n");
    printf("This is free software: you are free to change and redistribute it.\n");
    printf("Type \"help\" for a list of commands.\n");
}

static void print_prompt(void)
{
    printclr(FG_YELLOW, "BitFiend> ");
}

static void next_line(char *out, size_t n)
{
    fgets(out, n, stdin);
    out[n-1] = '\0';
    /* If input was too long, consume the rest of stdin buffer */
    if(out[strlen(out)-1] != '\n'){
        char c;
        while (((c = getchar()) != '\n') && (c != EOF));
    }
}

int main(int argc, char **argv)
{
    print_welcome();

    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    //if(bitfiend_init() != BITFIEND_SUCCESS){
    //    fpritnf("Failed initializing libbf. Check the logs!\n");
    //    exit(EXIT_FAILURE);
    //}


    while(true) {
        print_prompt();

        char line[256];
        next_line(line, sizeof(line));
        command_parse_and_exec(line);
    }

    //bitfiend_shutdown();
    return 0;


    bitfiend_add_torrent("/home/eduard/Downloads/ubuntu-16.04.2-desktop-amd64.iso.torrent", 
        "/home/eduard/Desktop");
    //bitfiend_add_torrent("/home/eduard/Downloads/TEST1.torrent", "/home/eduard/Desktop");

    while(running)
        ;

    bitfiend_shutdown();
}
