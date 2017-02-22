#include "bitfiend.h"

#include <signal.h>
#include <stdbool.h>

static bool running = true;

static void sig_handler(int signum)
{
    running = false; 
}

int main(int argc, char **argv)
{
    bitfiend_init();
    bitfiend_add_torrent("/home/eduard/Downloads/ubuntu.torrent");

    signal(SIGINT, sig_handler);
    while(running)
        ;

    bitfiend_shutdown();
}
