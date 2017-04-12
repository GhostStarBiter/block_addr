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


#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>


#define N_LOCKED_ADDR 256
#define ADDR_NAME_LEN 128
static const char CONFIG_FILE[] = "/opt/config.file";
static int addr_count;
static char forbidden[N_LOCKED_ADDR][ADDR_NAME_LEN];
static int readFile(char[][ADDR_NAME_LEN]);
static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = 0;

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
        if(readFile(forbidden) != 0){
            errno = EIO;
            return -1;
        }
        int sa_family = addr->sa_family;
        if (sa_family == AF_INET) {

            struct sockaddr_in *addr_in = (struct sockaddr_in *) (addr);
            struct in_addr sin_addr = addr_in->sin_addr;
            uint16_t sin_port = addr_in->sin_port;
            uint16_t sin_port_h = ntohs(sin_port);

            char host[ADDR_NAME_LEN];
            char serv[ADDR_NAME_LEN];
            int get_name = getnameinfo(addr, addrlen, host, ADDR_NAME_LEN, serv,ADDR_NAME_LEN,0);

            if (sin_port_h == 80 || sin_port_h == 443) {
                printf("\tREQUEST\t");
                int No = 0;
                char *p;
                while((host != NULL) && (forbidden[No][0] != 0)){
                    if((p=strstr(host, forbidden[No])) != NULL){
                        int adr_len = (int) strlen(forbidden[No]);
                        int temp_len = (int) (p - host);
                        if(host[temp_len + adr_len] < 47){
                            printf("TO %s BLOCKED.\n", host);
                            errno = ENETUNREACH;
                            return -1;
                        }
                    }
                    No++;
                }
                printf("TO %s ACCEPTED.\n", host);
            }
        }

    if(!real_connect)
        real_connect = dlsym(RTLD_NEXT, "connect");
    return real_connect(sockfd, addr, addrlen);
}


static int readFile(char forbidden[][ADDR_NAME_LEN]){
    FILE *cnfg;

    if((cnfg = fopen(CONFIG_FILE, "r")) == NULL){
        printf("Could not open config file: %s",strerror(errno));
        return -1;
    };
    char buf[ADDR_NAME_LEN] = {0};
    addr_count=0;
    int c, j=0;
    int char_count = 0, slash_count = 0;
    while(addr_count < N_LOCKED_ADDR &&
          j < ADDR_NAME_LEN &&
          (c = getc(cnfg)) != EOF){
        char_count++;
        if(c == '\n'){
            /** this is the case then newline appears before 8 characters have been read ( https:// )
             * it causes no internet address in variable buf **/
            if(buf[0] == 0 && char_count < 9)
                return -1;
            /** delete string "www" if it present on the beginning of the address**/
            if(strstr(buf, "www.") != NULL){
                int n = 0;
                while(buf[n+4] != 0){
                    buf[n] = buf[n+4];
                    n++;
                }
                for(int m = 1; m < 4+1; m++)
                    buf[n+4-m] = 0;
            }
            int buf_len = 0;
            while(buf[buf_len] != 0)
                buf_len++;
            /*
            if(buf[0] != '.'){
                int temp = buf_len;
                for(;temp >= 0; temp--)
                    buf[temp+1] = buf[temp];
                buf[0] = '.';
            }
             */
            while(buf[buf_len] != '.'){
                buf[buf_len] = 0;
                buf_len--;
            }
            buf[buf_len] = 0;

            for(int k=0; k < j+1; k++){
                forbidden[addr_count][k] = buf[k];
                forbidden[addr_count][k+1] = '\0';
            };
            addr_count++;
            j=0;
            slash_count = 0;
            int n = 0;
            while(n < ADDR_NAME_LEN)
                buf[n++] = 0;
        }
        else
        {
            if( c == 47 ){ // ASCII code of '/'
                slash_count++;
                continue;
            }
            if(slash_count == 2){
                buf[j] = (char) c;
                j++;
            }
        }
    }
    fclose(cnfg);
    return 0;
}
