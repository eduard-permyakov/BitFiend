# BitFiend #

BitFiend is a BitTorrent client written in C. It is multithread with POSIX threads. 
It can be built for Linux and has a command line interface. 

The client has successfully torrented Ubuntu ISOs and a number of academic torrents. 
At the moment, it lacks support for UDP trackers, accurate bandwidth reporting,
and various other nice-to-haves. I plan to add these featues and more in the future.

## Building BitFiend ##

To build the command-line client, run `make bfcli` in the top-level directory.

To build the core of BitFiend as a static library, run `make libbf` in the top-level
directory. The library API can be found in `libbf/bitfiend.h`

BitFiend does not depend on any third party libraries. It requires a C99 compiler with 
GNU extensions as well and POSIX compliance. Some non-portable Linux-specific code is
present.
