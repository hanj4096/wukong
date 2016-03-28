/* 
 * Copyright 2014-2015 Jerry Han (hanj4096@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 3 as 
 * published by the Free Software Foundation.
 *
 * Note: This kernel rootkit is just for educatinal purpose and it shouldn't be used for any illegal activities, use this at your own risk.
 */

#ifndef _UTIL_H_
#define _UTIL_H_

/*
static char * zalloc(size_t size) 
{
    char *ptr = NULL;
    
    if(size > 0) {
        ptr = malloc(size);
        if (ptr != NULL)
            memset(ptr, 0, size);
    }
    
    return ptr;
}
*/

static inline void daemonize()
{
    pid_t worker_pid;
    
    worker_pid = fork();
    if(worker_pid != 0) 
        exit(0);
}

static int write_pid_to_file(const char *file_path)
{
    FILE *fp;
    
    fp = fopen(file_path, "w");
    if(fp != NULL) {
        fprintf (fp, "%d\n", (int)getpid());    
        fclose(fp);
    }
    else {
        return -1;
    }
    
    return 0;
}

#endif
