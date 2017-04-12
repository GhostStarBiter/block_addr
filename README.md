# block_addr
block connection with sites specified in config.file

/**
 * This dynamic library intercept browser's call to function "connect".
 * To resolve the domain name used function getnameinfo().
 * Not all sites write requests to the servers with corresponding name.
 * that's why not all sites can be blocked with this dynamic lib.
 * (still working on it.)
 *
 * HOWTO (without IDE):
 *
 * 0. Create a file "config.file" with forbidden site names written in columns like
 * http://site1.com
 * https://site2.net
 * http://site3.us etc.
 *
 * and write the path to this file in const char variable CONFIG_FILE.
 * -----------------------------------------------------------------------------------
 *
 * PRINT IN TERMINAL:
 * 1. gcc -fPIC -shared -o libblock_addr.so library.c
 * 2. export LD_PRELOAD="full/path/to/file/libblock.so"
 * 3. call browser from command line.
 *
 * **/
